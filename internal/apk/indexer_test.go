package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
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

func writeTestAPK(t *testing.T, dir, name, version string) {
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
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	return index
}
