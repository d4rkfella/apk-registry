package registry

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestIndexWorkerBatchesUploadBursts(t *testing.T) {
	for _, packageCount := range []int{1, 10, 100} {
		t.Run(strconv.Itoa(packageCount), func(t *testing.T) {
			root := t.TempDir()
			packageDir := filepath.Join(root, "os", "x86_64")
			if err := os.MkdirAll(packageDir, 0755); err != nil {
				t.Fatal(err)
			}
			names := make([]string, packageCount)
			for i := range names {
				names[i] = fmt.Sprintf("package-%03d.apk", i)
				if err := os.WriteFile(filepath.Join(packageDir, names[i]), nil, 0644); err != nil {
					t.Fatal(err)
				}
			}
			indexPath := filepath.Join(packageDir, "APKINDEX.tar.gz")
			if err := os.WriteFile(indexPath, []byte("old index"), 0644); err != nil {
				t.Fatal(err)
			}

			generated := make(chan int, packageCount+1)
			manager := &Manager{
				root:      root,
				repo:      "os",
				indexName: "APKINDEX.tar.gz",
				log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
				indexer: indexerFunc(func(_ context.Context, snapshotDir, _, output, _ string) error {
					entries, err := os.ReadDir(snapshotDir)
					if err != nil {
						return err
					}
					if err := os.WriteFile(output, []byte("updated index"), 0644); err != nil {
						return err
					}
					select {
					case generated <- len(entries):
					default:
					}
					return nil
				}),
				states:   make(map[indexNamespace]*namespaceState),
				pending:  make(map[indexNamespace]indexWork),
				retrying: make(map[indexNamespace]indexRetry),
				wake:     make(chan struct{}, 1),
			}

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				manager.runIndexWorker(ctx)
				close(done)
			}()
			defer func() {
				cancel()
				<-done
			}()

			start := time.Now()
			ns := indexNamespace{arch: "x86_64"}
			for _, name := range names {
				manager.enqueueAddition(ns, name)
			}

			select {
			case indexedCount := <-generated:
				if indexedCount != packageCount {
					t.Fatalf("first index build included %d packages, want %d", indexedCount, packageCount)
				}
			case <-time.After(time.Second):
				t.Fatal("index was not generated within 1s")
			}

			deadline := time.Now().Add(time.Second)
			published := false
			for time.Now().Before(deadline) {
				data, err := os.ReadFile(indexPath)
				if err == nil && string(data) == "updated index" {
					elapsed := time.Since(start)
					if elapsed > time.Second {
						t.Fatalf("index became visible after %s, want under 1s", elapsed)
					}
					t.Logf("%d-package burst visible in %s", packageCount, elapsed)
					published = true
					break
				}
				time.Sleep(time.Millisecond)
			}
			if !published {
				t.Fatal("updated index was not published")
			}
			select {
			case indexedCount := <-generated:
				t.Fatalf("unexpected additional index generation for %d packages", indexedCount)
			case <-time.After(indexBatchWindow + 20*time.Millisecond):
			}
		})
	}
}

func TestIndexBatchWindowsAreIndependentByArchitecture(t *testing.T) {
	manager := &Manager{
		pending: make(map[indexNamespace]indexWork),
		wake:    make(chan struct{}, 1),
	}
	x86 := indexNamespace{arch: "x86_64"}
	arm := indexNamespace{arch: "aarch64"}
	manager.enqueueAddition(x86, "x86.apk")
	x86ReadyAt := manager.pending[x86].readyAt
	time.Sleep(time.Millisecond)
	manager.enqueueAddition(arm, "arm.apk")

	ns, _, ready := manager.nextIndex(x86ReadyAt)
	if !ready || ns != x86 {
		t.Fatalf("first ready architecture = %q, ready = %v; want x86_64, true", ns.arch, ready)
	}
	ns, work, ready := manager.nextIndex(x86ReadyAt)
	if ready || ns != arm || !work.readyAt.After(x86ReadyAt) {
		t.Fatalf("second architecture was delayed by the first batch deadline: namespace=%q ready=%v", ns.arch, ready)
	}
}

func TestIndexWorkerSelectsOldestReadyArchitecture(t *testing.T) {
	now := time.Now()
	oldest := indexNamespace{arch: "x86_64"}
	newer := indexNamespace{arch: "aarch64"}
	manager := &Manager{
		pending: map[indexNamespace]indexWork{
			oldest: {full: true, readyAt: now.Add(-2 * time.Millisecond)},
			newer:  {full: true, readyAt: now.Add(-time.Millisecond)},
		},
	}

	ns, _, ready := manager.nextIndex(now)
	if !ready || ns != oldest {
		t.Fatalf("first ready architecture = %q, ready = %v; want oldest x86_64 batch", ns.arch, ready)
	}
}

func BenchmarkEnqueueAdditionBurst(b *testing.B) {
	for _, packageCount := range []int{1, 10, 100} {
		b.Run(strconv.Itoa(packageCount), func(b *testing.B) {
			names := make([]string, packageCount)
			for i := range names {
				names[i] = fmt.Sprintf("package-%03d.apk", i)
			}
			manager := &Manager{
				pending: make(map[indexNamespace]indexWork),
				wake:    make(chan struct{}, 1),
			}
			ns := indexNamespace{arch: "x86_64"}

			b.ResetTimer()
			for b.Loop() {
				clear(manager.pending)
				for _, name := range names {
					manager.enqueueAddition(ns, name)
				}
				if got := len(manager.pending[ns].additions); got != packageCount {
					b.Fatalf("queued %d packages, want %d", got, packageCount)
				}
			}
		})
	}
}

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
