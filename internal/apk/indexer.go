package apk

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	apkoapk "chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/melange/pkg/index"
	"chainguard.dev/melange/pkg/sign"
	"golang.org/x/sync/errgroup"
)

type cachedIndex struct {
	fileInfo os.FileInfo
	index    apkoapk.APKIndex
}

type Indexer struct {
	SigningKey string

	mu    sync.Mutex
	cache map[string]cachedIndex
}

// BuildV2Merge merges package files into an existing APKINDEX when provided.
func (i *Indexer) BuildV2Merge(ctx context.Context, packageDir, existing, output, arch string) error {
	if existing == "" {
		i.invalidate(arch)
		return i.buildFull(ctx, packageDir, output, arch)
	}
	return i.buildIncremental(ctx, packageDir, existing, output, arch)
}

func (i *Indexer) buildFull(ctx context.Context, packageDir, output, arch string) error {
	options := []index.Option{
		index.WithPackageDir(packageDir),
		index.WithIndexFile(output),
		index.WithExpectedArch(arch),
	}
	if i.SigningKey != "" {
		options = append(options, index.WithSigningKey(i.SigningKey))
	}
	indexer, err := index.New(options...)
	if err != nil {
		return fmt.Errorf("configure melange indexer: %w", err)
	}
	if err := indexer.GenerateIndex(ctx); err != nil {
		return fmt.Errorf("generate APKINDEX: %w", err)
	}
	return nil
}

func (i *Indexer) buildIncremental(ctx context.Context, packageDir, existing, output, arch string) error {
	index, err := i.loadIndex(existing, arch)
	if err != nil {
		return fmt.Errorf("load existing APKINDEX: %w", err)
	}
	packages, err := parsePackages(ctx, packageDir, arch)
	if err != nil {
		return err
	}
	mergePackages(&index, packages)

	archive, err := apkoapk.ArchiveFromIndex(&index)
	if err != nil {
		return fmt.Errorf("create APKINDEX archive: %w", err)
	}
	out, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("create APKINDEX output: %w", err)
	}
	_, copyErr := io.Copy(out, archive)
	closeErr := out.Close()
	if copyErr != nil {
		return fmt.Errorf("write APKINDEX output: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close APKINDEX output: %w", closeErr)
	}
	if i.SigningKey != "" {
		if err := sign.SignIndex(ctx, i.SigningKey, output); err != nil {
			return fmt.Errorf("sign APKINDEX: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := i.cacheIndex(arch, output, index); err != nil {
		return err
	}
	return nil
}

func (i *Indexer) loadIndex(filename, arch string) (apkoapk.APKIndex, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return apkoapk.APKIndex{}, err
	}
	i.mu.Lock()
	cached, ok := i.cache[arch]
	if ok && sameFileVersion(cached.fileInfo, info) {
		index := cached.index
		index.Packages = append([]*apkoapk.Package(nil), cached.index.Packages...)
		i.mu.Unlock()
		return index, nil
	}
	if ok {
		delete(i.cache, arch)
	}
	i.mu.Unlock()

	file, err := os.Open(filename)
	if err != nil {
		return apkoapk.APKIndex{}, err
	}
	index, parseErr := apkoapk.IndexFromArchive(file)
	closeErr := file.Close()
	if parseErr != nil {
		return apkoapk.APKIndex{}, parseErr
	}
	if closeErr != nil {
		return apkoapk.APKIndex{}, closeErr
	}
	return *index, nil
}

func (i *Indexer) cacheIndex(arch, filename string, index apkoapk.APKIndex) error {
	info, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("stat generated APKINDEX: %w", err)
	}
	index.Packages = append([]*apkoapk.Package(nil), index.Packages...)
	i.mu.Lock()
	if i.cache == nil {
		i.cache = make(map[string]cachedIndex)
	}
	i.cache[arch] = cachedIndex{fileInfo: info, index: index}
	i.mu.Unlock()
	return nil
}

func (i *Indexer) invalidate(arch string) {
	i.mu.Lock()
	delete(i.cache, arch)
	i.mu.Unlock()
}

func sameFileVersion(cached, current os.FileInfo) bool {
	return cached != nil &&
		os.SameFile(cached, current) &&
		cached.Size() == current.Size() &&
		cached.ModTime().Equal(current.ModTime())
}

func parsePackages(ctx context.Context, packageDir, arch string) ([]*apkoapk.Package, error) {
	entries, err := os.ReadDir(packageDir)
	if err != nil {
		return nil, fmt.Errorf("list incremental APKs: %w", err)
	}
	filenames := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".apk") {
			filenames = append(filenames, filepath.Join(packageDir, entry.Name()))
		}
	}
	packages := make([]*apkoapk.Package, len(filenames))
	group, workCtx := errgroup.WithContext(ctx)
	group.SetLimit(4)
	for idx, filename := range filenames {
		idx, filename := idx, filename
		group.Go(func() error {
			if err := workCtx.Err(); err != nil {
				return err
			}
			file, err := os.Open(filename)
			if err != nil {
				return fmt.Errorf("open package %s: %w", filename, err)
			}
			info, err := file.Stat()
			if err != nil {
				file.Close()
				return fmt.Errorf("stat package %s: %w", filename, err)
			}
			pkg, parseErr := apkoapk.ParsePackage(workCtx, file, uint64(info.Size()))
			closeErr := file.Close()
			if parseErr != nil {
				return fmt.Errorf("parse package %s: %w", filename, parseErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close package %s: %w", filename, closeErr)
			}
			if pkg.Arch != arch {
				return fmt.Errorf("package %s has architecture %q, want %q", filename, pkg.Arch, arch)
			}
			packages[idx] = pkg
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return packages, nil
}

func mergePackages(index *apkoapk.APKIndex, additions []*apkoapk.Package) {
	type packageKey struct {
		name    string
		version string
	}
	positions := make(map[packageKey]int, len(index.Packages)+len(additions))
	for idx, pkg := range index.Packages {
		key := packageKey{name: pkg.Name, version: pkg.Version}
		if _, exists := positions[key]; !exists {
			positions[key] = idx
		}
	}
	for _, pkg := range additions {
		key := packageKey{name: pkg.Name, version: pkg.Version}
		if idx, exists := positions[key]; exists {
			index.Packages[idx] = pkg
			continue
		}
		positions[key] = len(index.Packages)
		index.Packages = append(index.Packages, pkg)
	}
}
