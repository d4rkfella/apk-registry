package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	apkoapk "chainguard.dev/apko/pkg/apk/apk"
	"github.com/d4rkfella/apk-registry/internal/apk"
	"github.com/d4rkfella/apk-registry/internal/config"
	"github.com/d4rkfella/apk-registry/internal/repository"
)

var errOverwriteDenied = errors.New("delete permission is required to overwrite an existing package")
var errInvalidPackagePath = errors.New("package path is invalid")
var errUnsupportedArchitecture = errors.New("unsupported package architecture")
var errPackageTooLarge = errors.New("package exceeds maximum upload size")
var errInvalidAPK = errors.New("invalid APK")

type indexBuilder interface {
	BuildV2Merge(context.Context, string, string, string, string) error
}

type Manager struct {
	root       string
	repo       string
	indexName  string
	indexer    indexBuilder
	maxUpload  int64
	log        *slog.Logger
	signingKey *signingKeyInfo

	stateMu   sync.Mutex
	states    map[indexNamespace]*namespaceState
	queueMu   sync.Mutex
	pending   map[indexNamespace]indexWork
	retrying  map[indexNamespace]indexRetry
	retrySeq  uint64
	wake      chan struct{}
	startOnce sync.Once
}

type Package struct {
	Filename     string `json:"filename"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
}

func NewManager(cfg config.Config, log *slog.Logger) (*Manager, error) {
	if log == nil {
		log = slog.Default()
	}
	var signingKey *signingKeyInfo
	if cfg.SigningKey != "" {
		var err error
		signingKey, err = loadSigningKey(cfg.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("load APK index signing key: %w", err)
		}
	}
	root, err := filepath.Abs(cfg.StorageRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve storage root: %w", err)
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		return nil, fmt.Errorf("create storage root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve storage root symlinks: %w", err)
	}
	return &Manager{
		root:       root,
		repo:       cfg.Repository,
		indexName:  "APKINDEX.tar.gz",
		indexer:    apk.Indexer{SigningKey: cfg.SigningKey},
		maxUpload:  cfg.MaxUploadSize,
		log:        log,
		signingKey: signingKey,
		states:     make(map[indexNamespace]*namespaceState),
		pending:    make(map[indexNamespace]indexWork),
		retrying:   make(map[indexNamespace]indexRetry),
		wake:       make(chan struct{}, 1),
	}, nil
}

func (m *Manager) Start(ctx context.Context) {
	m.startOnce.Do(func() {
		go m.runIndexWorker(ctx)
		go m.enqueueExisting(ctx)
	})
}

func (m *Manager) PrivateStatePath() string {
	return filepath.Join(m.root, "_registry", "api-keys.json")
}

func (m *Manager) Read(ctx context.Context, repo, relative string) (*os.File, string, error) {
	if repo != m.repo {
		return nil, "", os.ErrNotExist
	}
	_, _, isPackage := repository.ParsePackagePath(relative)
	arch, isIndex := repository.ParseIndexPath(relative, m.indexName)
	if !isPackage {
		if !isIndex {
			return nil, "", errInvalidPackagePath
		}
	}
	key := repo + "/" + relative
	filename := path.Base(relative)
	file, err := m.openFile(key)
	if errors.Is(err, os.ErrNotExist) && isIndex {
		if err := m.ensureEmptyIndex(ctx, repo, relative, arch); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				m.log.Error("generate empty package index", "repository", repo, "architecture", arch, "error", err)
			}
			return nil, "", err
		}
		file, err = m.openFile(key)
	}
	if err != nil {
		return nil, "", err
	}
	if err := ctx.Err(); err != nil {
		file.Close()
		return nil, "", err
	}
	return file, filename, nil
}

func (m *Manager) ensureEmptyIndex(ctx context.Context, repo, relative, arch string) error {
	if !repository.SupportedArchitecture(arch) {
		return os.ErrNotExist
	}
	indexPath, err := m.pathFor(path.Join(repo, relative), true)
	if err != nil {
		return err
	}
	packageDir := filepath.Dir(indexPath)
	state := m.namespaceState(indexNamespace{arch: arch})
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}

	if info, err := os.Lstat(indexPath); err == nil {
		if info.Mode().IsRegular() {
			return nil
		}
		return errors.New("index target is not a regular file")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	entries, err := os.ReadDir(packageDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".apk") {
			return os.ErrNotExist
		}
	}

	outputFile, err := os.CreateTemp(packageDir, ".index-output-*")
	if err != nil {
		return err
	}
	outputPath := outputFile.Name()
	if err := outputFile.Close(); err != nil {
		os.Remove(outputPath)
		return err
	}
	if err := os.Remove(outputPath); err != nil {
		return err
	}
	defer os.Remove(outputPath)
	defer os.Remove(outputPath + ".tmp")

	if err := m.indexer.BuildV2Merge(ctx, packageDir, "", outputPath, arch); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.Rename(outputPath, indexPath)
}

func (m *Manager) Upload(ctx context.Context, repo, relative string, allowOverwrite bool, body io.Reader) (Package, error) {
	if repo != m.repo || !repository.ValidSegment(repo) {
		return Package{}, errInvalidPackagePath
	}
	arch, filename, ok := repository.ParsePackagePath(relative)
	if !ok {
		return Package{}, errInvalidPackagePath
	}
	if !repository.SupportedArchitecture(arch) {
		return Package{}, fmt.Errorf("%w: %q", errUnsupportedArchitecture, arch)
	}
	ns := indexNamespace{arch: arch}
	packageKey := path.Join(arch, filename)
	indexKey := path.Join(arch, m.indexName)

	target, err := m.pathFor(path.Join(repo, packageKey), true)
	if err != nil {
		return Package{}, err
	}
	if _, err := m.pathFor(path.Join(repo, indexKey), true); err != nil {
		return Package{}, err
	}
	state := m.namespaceState(ns)
	state.mu.RLock()
	oldInfo, oldErr := os.Lstat(target)
	state.mu.RUnlock()
	if oldErr != nil && !errors.Is(oldErr, os.ErrNotExist) {
		return Package{}, oldErr
	}
	if oldErr == nil {
		if !oldInfo.Mode().IsRegular() {
			return Package{}, errors.New("package target is not a regular file")
		}
		if !allowOverwrite {
			return Package{}, errOverwriteDenied
		}
	}

	temp, err := os.CreateTemp(filepath.Dir(target), ".upload-*")
	if err != nil {
		return Package{}, err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	hash := sha256.New()
	limit := m.maxUpload
	if limit < int64(^uint64(0)>>1) {
		limit++
	}
	size, err := io.Copy(io.MultiWriter(temp, hash), io.LimitReader(body, limit))
	if err == nil && size > m.maxUpload {
		err = fmt.Errorf("%w of %d bytes", errPackageTooLarge, m.maxUpload)
	}
	if err == nil {
		err = temp.Chmod(0644)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return Package{}, err
	}
	if err := ctx.Err(); err != nil {
		return Package{}, err
	}
	file, err := os.Open(tempName)
	if err != nil {
		return Package{}, err
	}
	apkPackage, metaErr := apkoapk.ParsePackage(ctx, file, uint64(size))
	closeErr := file.Close()
	if metaErr != nil {
		return Package{}, fmt.Errorf("%w: %v", errInvalidAPK, metaErr)
	}
	if closeErr != nil {
		return Package{}, closeErr
	}
	metadata := repository.APKMetadata{Name: apkPackage.Name, Version: apkPackage.Version, Arch: apkPackage.Arch}
	if apkPackage.Arch != arch {
		return Package{}, fmt.Errorf("%w: architecture %q does not match path architecture %q", errInvalidAPK, apkPackage.Arch, arch)
	}
	if !repository.FilenameMatchesAPKMetadata(filename, metadata) {
		return Package{}, fmt.Errorf("%w: metadata %s-%s does not match filename %s", errInvalidAPK, metadata.Name, metadata.Version, filename)
	}

	state.mu.Lock()
	if err := ctx.Err(); err != nil {
		state.mu.Unlock()
		return Package{}, err
	}
	oldInfo, oldErr = os.Lstat(target)
	if oldErr != nil && !errors.Is(oldErr, os.ErrNotExist) {
		state.mu.Unlock()
		return Package{}, oldErr
	}
	if oldErr == nil {
		if !oldInfo.Mode().IsRegular() {
			state.mu.Unlock()
			return Package{}, errors.New("package target is not a regular file")
		}
		if !allowOverwrite {
			state.mu.Unlock()
			return Package{}, errOverwriteDenied
		}
	}
	overwriting := oldErr == nil
	if err := os.Rename(tempName, target); err != nil {
		state.mu.Unlock()
		return Package{}, err
	}
	state.version++
	state.mu.Unlock()
	if overwriting {
		m.enqueueIndex(ns)
	} else {
		m.enqueueAddition(ns, filename)
	}
	return Package{
		Filename: filename, Name: metadata.Name, Version: metadata.Version,
		Architecture: metadata.Arch, SHA256: hex.EncodeToString(hash.Sum(nil)), Size: size,
	}, nil
}

func (m *Manager) Delete(ctx context.Context, repo, relative string) error {
	if repo != m.repo || !repository.ValidSegment(repo) {
		return errInvalidPackagePath
	}
	arch, filename, ok := repository.ParsePackagePath(relative)
	if !ok {
		return errInvalidPackagePath
	}
	ns := indexNamespace{arch: arch}
	packageKey := path.Join(arch, filename)
	indexKey := path.Join(arch, m.indexName)
	if _, err := m.pathFor(path.Join(repo, indexKey), true); err != nil {
		return err
	}
	target, err := m.pathFor(path.Join(repo, packageKey), false)
	if err != nil {
		return err
	}
	state := m.namespaceState(ns)
	state.mu.Lock()
	if err := ctx.Err(); err != nil {
		state.mu.Unlock()
		return err
	}
	info, err := os.Lstat(target)
	if err != nil {
		state.mu.Unlock()
		return err
	}
	if !info.Mode().IsRegular() {
		state.mu.Unlock()
		return errors.New("package target is not a regular file")
	}
	if err := os.Remove(target); err != nil {
		state.mu.Unlock()
		return err
	}
	state.version++
	state.mu.Unlock()
	m.enqueueIndex(ns)
	return nil
}

func (m *Manager) openFile(key string) (*os.File, error) {
	filename, err := m.pathFor(key, false)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("requested path is not a regular file")
	}
	return os.Open(filename)
}

func (m *Manager) pathFor(key string, createDirs bool) (string, error) {
	if key == "" || strings.ContainsAny(key, `\`) || strings.HasPrefix(key, "/") {
		return "", errInvalidPackagePath
	}
	parts := strings.Split(key, "/")
	current := m.root
	for index, part := range parts {
		if !repository.ValidSegment(part) {
			return "", errInvalidPackagePath
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && createDirs && index < len(parts)-1 {
			if err := os.Mkdir(current, 0755); err != nil && !errors.Is(err, os.ErrExist) {
				return "", err
			}
			info, err = os.Lstat(current)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("symbolic links are not allowed in package paths")
		}
		if err == nil && index < len(parts)-1 && !info.IsDir() {
			return "", errors.New("package path parent is not a directory")
		}
	}
	return current, nil
}

func isEmptyAPKIndex(filename string) (bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer file.Close()
	index, err := apkoapk.IndexFromArchive(file)
	if err != nil {
		return false, err
	}
	return len(index.Packages) == 0, nil
}
