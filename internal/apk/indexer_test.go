package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	apkoapk "chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/melange/pkg/index"
)

func TestIncrementalMergeMatchesMelange(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	baseDir := filepath.Join(root, "base")
	additionsDir := filepath.Join(root, "additions")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(additionsDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestAPK(t, baseDir, "existing", "1.0-r0")
	writeTestAPK(t, additionsDir, "added-one", "1.0-r0")
	writeTestAPK(t, additionsDir, "added-two", "2.0-r0")

	baseIndexPath := filepath.Join(root, "base-index.tar.gz")
	indexer := &Indexer{}
	if err := indexer.BuildV2Merge(ctx, baseDir, "", baseIndexPath, "x86_64"); err != nil {
		t.Fatalf("build baseline index: %v", err)
	}

	cachedOutputPath := filepath.Join(root, "cached-index.tar.gz")
	if err := indexer.BuildV2Merge(ctx, additionsDir, baseIndexPath, cachedOutputPath, "x86_64"); err != nil {
		t.Fatalf("build cached incremental index: %v", err)
	}

	melangeOutputPath := filepath.Join(root, "melange-index.tar.gz")
	melangeIndexer, err := index.New(
		index.WithPackageDir(additionsDir),
		index.WithIndexFile(melangeOutputPath),
		index.WithExpectedArch("x86_64"),
		index.WithSourceIndexFile(baseIndexPath),
		index.WithMergeIndexFileFlag(true),
	)
	if err != nil {
		t.Fatalf("configure Melange indexer: %v", err)
	}
	if err := melangeIndexer.GenerateIndex(ctx); err != nil {
		t.Fatalf("build reference Melange index: %v", err)
	}

	cachedIndex := readTestIndex(t, cachedOutputPath)
	melangeIndex := readTestIndex(t, melangeOutputPath)
	if !reflect.DeepEqual(cachedIndex, melangeIndex) {
		t.Fatal("cached incremental index records differ from Melange output")
	}
}

func TestIncrementalBuildRespectsCanceledContext(t *testing.T) {
	root := t.TempDir()
	baseDir := filepath.Join(root, "base")
	additionsDir := filepath.Join(root, "additions")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(additionsDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestAPK(t, baseDir, "existing", "1.0-r0")
	writeTestAPK(t, additionsDir, "addition", "1.0-r0")

	indexer := &Indexer{}
	existing := filepath.Join(root, "existing-index.tar.gz")
	if err := indexer.BuildV2Merge(context.Background(), baseDir, "", existing, "x86_64"); err != nil {
		t.Fatalf("build baseline index: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	output := filepath.Join(root, "output-index.tar.gz")
	err := indexer.BuildV2Merge(ctx, additionsDir, existing, output, "x86_64")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("incremental build error = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled build output stat error = %v, want os.ErrNotExist", err)
	}
}

func TestIncrementalBuildRejectsCorruptPackage(t *testing.T) {
	root := t.TempDir()
	baseDir := filepath.Join(root, "base")
	additionsDir := filepath.Join(root, "additions")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(additionsDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestAPK(t, baseDir, "existing", "1.0-r0")
	if err := os.WriteFile(filepath.Join(additionsDir, "corrupt-1.0-r0.apk"), []byte("not an APK"), 0644); err != nil {
		t.Fatal(err)
	}

	indexer := &Indexer{}
	existing := filepath.Join(root, "existing-index.tar.gz")
	if err := indexer.BuildV2Merge(context.Background(), baseDir, "", existing, "x86_64"); err != nil {
		t.Fatalf("build baseline index: %v", err)
	}
	output := filepath.Join(root, "output-index.tar.gz")
	if err := indexer.BuildV2Merge(context.Background(), additionsDir, existing, output, "x86_64"); err == nil {
		t.Fatal("incremental build accepted a corrupt APK")
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt build output stat error = %v, want os.ErrNotExist", err)
	}
}

func TestIncrementalBuildInvalidatesChangedIndexCache(t *testing.T) {
	root := t.TempDir()
	baseDir := filepath.Join(root, "base")
	firstAdditions := filepath.Join(root, "first-additions")
	replacementDir := filepath.Join(root, "replacement")
	nextAdditions := filepath.Join(root, "next-additions")
	for _, dir := range []string{baseDir, firstAdditions, replacementDir, nextAdditions} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeTestAPK(t, baseDir, "original", "1.0-r0")
	writeTestAPK(t, firstAdditions, "first-addition", "1.0-r0")
	writeTestAPK(t, replacementDir, "replacement", "1.0-r0")
	writeTestAPK(t, nextAdditions, "next-addition", "1.0-r0")

	indexer := &Indexer{}
	existing := filepath.Join(root, "existing-index.tar.gz")
	if err := indexer.BuildV2Merge(context.Background(), baseDir, "", existing, "x86_64"); err != nil {
		t.Fatalf("build baseline index: %v", err)
	}
	output := filepath.Join(root, "output-index.tar.gz")
	if err := indexer.BuildV2Merge(context.Background(), firstAdditions, existing, output, "x86_64"); err != nil {
		t.Fatalf("build initial incremental index: %v", err)
	}
	if err := os.Rename(output, existing); err != nil {
		t.Fatalf("publish initial incremental index: %v", err)
	}

	replacementIndex := filepath.Join(root, "replacement-index.tar.gz")
	if err := (&Indexer{}).BuildV2Merge(context.Background(), replacementDir, "", replacementIndex, "x86_64"); err != nil {
		t.Fatalf("build replacement index: %v", err)
	}
	if err := os.Rename(replacementIndex, existing); err != nil {
		t.Fatalf("replace cached index: %v", err)
	}

	if err := indexer.BuildV2Merge(context.Background(), nextAdditions, existing, output, "x86_64"); err != nil {
		t.Fatalf("build after index replacement: %v", err)
	}
	index := readTestIndex(t, output)
	names := make(map[string]bool, len(index.Packages))
	for _, pkg := range index.Packages {
		names[pkg.Name] = true
	}
	if len(names) != 2 || !names["replacement"] || !names["next-addition"] {
		t.Fatalf("index package names = %v, want replacement and next-addition only", names)
	}
}

func BenchmarkBuildV2Merge(b *testing.B) {
	for _, packageCount := range []int{10, 100, 500} {
		b.Run(fmt.Sprintf("warm-cache-%d-packages", packageCount), func(b *testing.B) {
			root := b.TempDir()
			baseDir := filepath.Join(root, "base")
			additionsDir := filepath.Join(root, "additions")
			if err := os.MkdirAll(baseDir, 0755); err != nil {
				b.Fatal(err)
			}
			if err := os.MkdirAll(additionsDir, 0755); err != nil {
				b.Fatal(err)
			}
			for idx := 0; idx < packageCount-1; idx++ {
				writeTestAPK(b, baseDir, fmt.Sprintf("pkg-%04d", idx), "1.0-r0")
			}
			writeTestAPK(b, additionsDir, "incremental", "1.0-r0")

			indexer := &Indexer{}
			existing := filepath.Join(root, "existing-index.tar.gz")
			if err := indexer.BuildV2Merge(context.Background(), baseDir, "", existing, "x86_64"); err != nil {
				b.Fatalf("build baseline index: %v", err)
			}
			output := filepath.Join(root, "output-index.tar.gz")
			buildAndPublish := func() {
				b.Helper()
				if err := indexer.BuildV2Merge(context.Background(), additionsDir, existing, output, "x86_64"); err != nil {
					b.Fatalf("build incremental index: %v", err)
				}
				if err := os.Rename(output, existing); err != nil {
					b.Fatalf("publish incremental index: %v", err)
				}
			}
			buildAndPublish()

			b.ReportAllocs()
			b.ResetTimer()
			for idx := 0; idx < b.N; idx++ {
				buildAndPublish()
			}
		})
	}
}

func writeTestAPK(t testing.TB, dir, name, version string) {
	t.Helper()
	info := []byte("pkgname = " + name + "\npkgver = " + version + "\narch = x86_64\n")
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compressed)
	if err := archive.WriteHeader(&tar.Header{Name: ".PKGINFO", Mode: 0644, Size: int64(len(info))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(info); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(dir, name+"-"+version+".apk")
	if err := os.WriteFile(filename, buffer.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
}

func readTestIndex(t *testing.T, filename string) *apkoapk.APKIndex {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	index, parseErr := apkoapk.IndexFromArchive(file)
	closeErr := file.Close()
	if parseErr != nil || closeErr != nil {
		t.Fatal(errors.Join(parseErr, closeErr))
	}
	return index
}
