package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/d4rkfella/apk-registry/internal/apk"
	"github.com/d4rkfella/apk-registry/internal/config"
)

func TestFailedIndexBuildPreservesPublishedIndex(t *testing.T) {
	buildErr := errors.New("injected indexer failure")
	tests := []struct {
		name             string
		buildErr         error
		cancelAfterWrite bool
		wantErr          error
	}{
		{name: "builder error", buildErr: buildErr, wantErr: buildErr},
		{name: "canceled after output", cancelAfterWrite: true, wantErr: context.Canceled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			manager, err := NewManager(config.Config{
				StorageRoot: root, Repository: "os", MaxUploadSize: 1 << 20,
			}, log)
			if err != nil {
				t.Fatal(err)
			}
			packageDir := filepath.Join(root, "os", "x86_64")
			if err := os.MkdirAll(packageDir, 0755); err != nil {
				t.Fatal(err)
			}
			emptyDir := filepath.Join(root, "empty")
			if err := os.MkdirAll(emptyDir, 0755); err != nil {
				t.Fatal(err)
			}
			startupCtx := clog.WithLogger(context.Background(), clog.New(slog.NewTextHandler(io.Discard, nil)))
			indexPath := filepath.Join(packageDir, "APKINDEX.tar.gz")
			if err := manager.indexer.BuildV2Merge(startupCtx, emptyDir, "", indexPath, "x86_64"); err != nil {
				t.Fatalf("create previously published index: %v", err)
			}
			publishedIndex, err := os.ReadFile(indexPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(packageDir, "package-1.0-r0.apk"), []byte("package"), 0644); err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			manager.indexer = indexerFunc(func(_ context.Context, _, _, output, _ string) error {
				if err := os.WriteFile(output, []byte("partial replacement"), 0644); err != nil {
					return err
				}
				if tt.cancelAfterWrite {
					cancel()
				}
				return tt.buildErr
			})

			published, err := manager.buildAndPublishIndex(ctx, indexNamespace{arch: "x86_64"}, indexWork{full: true})
			if published || !errors.Is(err, tt.wantErr) {
				t.Fatalf("build result = (%v, %v), want (false, %v)", published, err, tt.wantErr)
			}
			gotIndex, err := os.ReadFile(indexPath)
			if err != nil {
				t.Fatalf("read previously published index: %v", err)
			}
			if !bytes.Equal(gotIndex, publishedIndex) {
				t.Fatalf("published index changed after failed build: %q", gotIndex)
			}
			if index, err := readAPKIndex(indexPath); err != nil || strings.TrimSpace(index) != "" {
				t.Fatalf("previously published index is no longer a valid empty index: %q, %v", index, err)
			}
			entries, err := os.ReadDir(packageDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 2 {
				t.Fatalf("temporary index artifacts remain after failed build: %v", entries)
			}
		})
	}
}

func TestStartupRecoveryRebuildsStaleIndex(t *testing.T) {
	root := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := NewManager(config.Config{
		StorageRoot: root, Repository: "os", MaxUploadSize: 1 << 20,
	}, log)
	if err != nil {
		t.Fatal(err)
	}

	packageDir := filepath.Join(root, "os", "x86_64")
	if err := os.MkdirAll(packageDir, 0755); err != nil {
		t.Fatal(err)
	}
	emptyDir := filepath.Join(root, "empty")
	if err := os.MkdirAll(emptyDir, 0755); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(packageDir, "APKINDEX.tar.gz")
	startupCtx := clog.WithLogger(context.Background(), clog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := manager.indexer.BuildV2Merge(startupCtx, emptyDir, "", indexPath, "x86_64"); err != nil {
		t.Fatalf("create stale empty index: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(packageDir, "recovered-1.0-r0.apk"),
		testAPK(t, "recovered", "1.0-r0", "x86_64"),
		0644,
	); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(startupCtx)
	manager.Start(ctx)
	defer func() {
		cancel()
		manager.Wait()
	}()

	waitFor(t, "startup recovery of stale index", func() bool {
		index, err := readAPKIndex(indexPath)
		return err == nil && strings.Contains(index, "P:recovered\n")
	})
}

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

func BenchmarkMelangeIndexGeneration(b *testing.B) {
	for _, existingCount := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("existing-%d", existingCount), func(b *testing.B) {
			ctx := clog.WithLogger(context.Background(), clog.New(slog.NewTextHandler(io.Discard, nil)))
			baseRoot := b.TempDir()
			packageDir := filepath.Join(baseRoot, "os", "x86_64")
			if err := os.MkdirAll(packageDir, 0755); err != nil {
				b.Fatal(err)
			}
			var compressed bytes.Buffer
			gzipWriter := gzip.NewWriter(&compressed)
			for i := 0; i < existingCount; i++ {
				name := fmt.Sprintf("existing-%05d", i)
				filename := filepath.Join(packageDir, name+"-1.0-r0.apk")
				writeIndexBenchmarkAPK(b, filename, name, "x86_64", &compressed, gzipWriter)
			}

			baseIndexPath := filepath.Join(packageDir, "APKINDEX.tar.gz")
			indexer := &apk.Indexer{}
			if err := indexer.BuildV2Merge(ctx, packageDir, "", baseIndexPath, "x86_64"); err != nil {
				b.Fatalf("build %d-package baseline index: %v", existingCount, err)
			}
			baseIndex, err := os.ReadFile(baseIndexPath)
			if err != nil {
				b.Fatal(err)
			}

			b.Run("full", func(b *testing.B) {
				manager := &Manager{
					root:      baseRoot,
					repo:      "os",
					indexName: "APKINDEX.tar.gz",
					indexer:   indexer,
					states:    make(map[indexNamespace]*namespaceState),
				}
				work := indexWork{full: true}
				ns := indexNamespace{arch: "x86_64"}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					published, err := manager.buildAndPublishIndex(ctx, ns, work)
					if err != nil {
						b.Fatal(err)
					}
					if !published {
						b.Fatal("full index build was not published")
					}
				}
				b.ReportMetric(float64(existingCount), "existing-pkgs/op")
			})

			for _, addedCount := range []int{1, 10, 100} {
				b.Run(fmt.Sprintf("incremental-%d", addedCount), func(b *testing.B) {
					root := b.TempDir()
					incrementalDir := filepath.Join(root, "os", "x86_64")
					if err := os.MkdirAll(incrementalDir, 0755); err != nil {
						b.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(incrementalDir, "APKINDEX.tar.gz"), baseIndex, 0644); err != nil {
						b.Fatal(err)
					}
					work := indexWork{additions: make(map[string]struct{}, addedCount)}
					var compressed bytes.Buffer
					gzipWriter := gzip.NewWriter(&compressed)
					for i := 0; i < addedCount; i++ {
						name := fmt.Sprintf("added-%03d", i)
						filename := name + "-1.0-r0.apk"
						writeIndexBenchmarkAPK(b, filepath.Join(incrementalDir, filename), name, "x86_64", &compressed, gzipWriter)
						work.additions[filename] = struct{}{}
					}
					manager := &Manager{
						root:      root,
						repo:      "os",
						indexName: "APKINDEX.tar.gz",
						indexer:   indexer,
						states:    make(map[indexNamespace]*namespaceState),
					}
					ns := indexNamespace{arch: "x86_64"}
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						published, err := manager.buildAndPublishIndex(ctx, ns, work)
						if err != nil {
							b.Fatal(err)
						}
						if !published {
							b.Fatal("incremental index build was not published")
						}
					}
					b.ReportMetric(float64(existingCount), "existing-pkgs/op")
					b.ReportMetric(float64(addedCount), "added-pkgs/op")
				})
			}
		})
	}
}

func writeIndexBenchmarkAPK(b *testing.B, filename, name, arch string, compressed *bytes.Buffer, gzipWriter *gzip.Writer) {
	b.Helper()
	compressed.Reset()
	gzipWriter.Reset(compressed)
	info := fmt.Appendf(nil, "pkgname = %s\npkgver = 1.0-r0\narch = %s\n", name, arch)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: ".PKGINFO", Mode: 0644, Size: int64(len(info))}); err != nil {
		b.Fatal(err)
	}
	if _, err := tarWriter.Write(info); err != nil {
		b.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		b.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filename, compressed.Bytes(), 0644); err != nil {
		b.Fatal(err)
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
