package registry

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestIncrementalIndexSnapshotIncludesOnlyQueuedPackages(t *testing.T) {
	root := t.TempDir()
	packageDir := filepath.Join(root, "os", "x86_64")
	if err := os.MkdirAll(packageDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{"existing-package.apk", "new-package.apk"} {
		if err := os.WriteFile(filepath.Join(packageDir, filename), nil, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(packageDir, "APKINDEX.tar.gz"), []byte("index"), 0644); err != nil {
		t.Fatal(err)
	}

	var indexedPackages []string
	manager := &Manager{
		root:      root,
		repo:      "os",
		indexName: "APKINDEX.tar.gz",
		indexer: indexerFunc(func(_ context.Context, snapshotDir, _, output, _ string) error {
			entries, err := os.ReadDir(snapshotDir)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				indexedPackages = append(indexedPackages, entry.Name())
			}
			return os.WriteFile(output, []byte("updated index"), 0644)
		}),
		states: make(map[indexNamespace]*namespaceState),
	}

	published, err := manager.buildAndPublishIndex(
		context.Background(),
		indexNamespace{arch: "x86_64"},
		indexWork{additions: map[string]struct{}{"new-package.apk": {}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !published {
		t.Fatal("index build was not published")
	}
	if len(indexedPackages) != 1 || indexedPackages[0] != "new-package.apk" {
		t.Fatalf("indexed packages = %v, want only new-package.apk", indexedPackages)
	}
}

func BenchmarkIncrementalIndexSnapshot(b *testing.B) {
	root := b.TempDir()
	packageDir := filepath.Join(root, "os", "x86_64")
	if err := os.MkdirAll(packageDir, 0755); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 10_000; i++ {
		filename := filepath.Join(packageDir, "package-"+strconv.Itoa(i)+".apk")
		if err := os.WriteFile(filename, nil, 0644); err != nil {
			b.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(packageDir, "new-package.apk"), nil, 0644); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "APKINDEX.tar.gz"), []byte("index"), 0644); err != nil {
		b.Fatal(err)
	}

	manager := &Manager{
		root:      root,
		repo:      "os",
		indexName: "APKINDEX.tar.gz",
		indexer: indexerFunc(func(_ context.Context, _, _, output, _ string) error {
			return os.WriteFile(output, []byte("updated index"), 0644)
		}),
		states: make(map[indexNamespace]*namespaceState),
	}
	ctx := context.Background()
	ns := indexNamespace{arch: "x86_64"}
	work := indexWork{additions: map[string]struct{}{"new-package.apk": {}}}

	for b.Loop() {
		published, err := manager.buildAndPublishIndex(ctx, ns, work)
		if err != nil {
			b.Fatal(err)
		}
		if !published {
			b.Fatal("index build was not published")
		}
	}
}
