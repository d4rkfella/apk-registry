package registry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/d4rkfella/apk-registry/internal/repository"
)

type indexNamespace struct {
	arch string
}

type namespaceState struct {
	mu      sync.RWMutex
	version uint64
}

type indexWork struct {
	full      bool
	additions map[string]struct{}
	readyAt   time.Time
}

type indexRetry struct {
	id   uint64
	work indexWork
}

const indexBatchWindow = 100 * time.Millisecond

func (m *Manager) namespaceState(ns indexNamespace) *namespaceState {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	state := m.states[ns]
	if state == nil {
		state = &namespaceState{}
		m.states[ns] = state
	}
	return state
}

func (m *Manager) enqueueIndex(ns indexNamespace) {
	m.enqueueWork(ns, indexWork{full: true})
}

func (m *Manager) enqueueAddition(ns indexNamespace, filename string) {
	m.queueMu.Lock()
	work, exists := m.pending[ns]
	if !exists {
		work.readyAt = time.Now().Add(indexBatchWindow)
	}
	if !work.full {
		if work.additions == nil {
			work.additions = make(map[string]struct{})
		}
		work.additions[filename] = struct{}{}
	}
	m.pending[ns] = work
	m.queueMu.Unlock()
	m.signalIndexWorker()
}

func (m *Manager) enqueueWork(ns indexNamespace, work indexWork) {
	m.queueMu.Lock()
	if _, exists := m.pending[ns]; !exists {
		work.readyAt = time.Now().Add(indexBatchWindow)
	}
	m.pending[ns] = mergeIndexWork(m.pending[ns], work)
	m.queueMu.Unlock()
	m.signalIndexWorker()
}

func (m *Manager) signalIndexWorker() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func mergeIndexWork(first, second indexWork) indexWork {
	readyAt := first.readyAt
	if readyAt.IsZero() || (!second.readyAt.IsZero() && second.readyAt.Before(readyAt)) {
		readyAt = second.readyAt
	}
	if first.full || second.full {
		return indexWork{full: true, readyAt: readyAt}
	}
	if len(second.additions) == 0 {
		first.readyAt = readyAt
		return first
	}
	if first.additions == nil {
		first.additions = make(map[string]struct{}, len(second.additions))
	}
	for filename := range second.additions {
		first.additions[filename] = struct{}{}
	}
	first.readyAt = readyAt
	return first
}

func (m *Manager) nextIndex(now time.Time) (indexNamespace, indexWork, bool) {
	m.queueMu.Lock()
	defer m.queueMu.Unlock()
	var earliestNS indexNamespace
	var earliestWork indexWork
	hasPending := false
	for ns, work := range m.pending {
		if !hasPending || work.readyAt.Before(earliestWork.readyAt) {
			earliestNS = ns
			earliestWork = work
			hasPending = true
		}
	}
	if hasPending && !earliestWork.readyAt.After(now) {
		delete(m.pending, earliestNS)
		return earliestNS, earliestWork, true
	}
	if hasPending {
		return earliestNS, earliestWork, false
	}
	return indexNamespace{}, indexWork{}, false
}

func (m *Manager) runIndexWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		}
		for {
			ns, work, ok := m.nextIndex(time.Now())
			if !ok {
				if work.readyAt.IsZero() {
					break
				}
				timer := time.NewTimer(time.Until(work.readyAt))
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-m.wake:
					timer.Stop()
				case <-timer.C:
				}
				continue
			}
			buildStarted := time.Now()
			published, err := m.buildAndPublishIndex(ctx, ns, work)
			buildDuration := time.Since(buildStarted)
			outcome := "superseded"
			if err != nil {
				outcome = "failure"
			} else if published {
				outcome = "success"
			}
			if m.metrics != nil {
				m.metrics.observeIndexBuild(ns.arch, outcome, buildDuration)
			}
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				m.log.Error("APK index build failed", "repository", m.repo, "architecture", ns.arch, "duration_ms", float64(buildDuration.Microseconds())/1000, "retry_delay", 5*time.Second, "error", err)
				m.retryIndex(ctx, ns, indexWork{full: true})
				continue
			}
			if !published {
				m.enqueueIndex(ns)
				continue
			}
			m.log.Info("APK index published", "repository", m.repo, "architecture", ns.arch, "duration_ms", float64(buildDuration.Microseconds())/1000)
			m.cancelIndexRetry(ns)
		}
	}
}

func (m *Manager) retryIndex(ctx context.Context, ns indexNamespace, work indexWork) {
	if m.metrics != nil {
		m.metrics.observeIndexRetry(ns.arch)
	}
	m.queueMu.Lock()
	m.retrySeq++
	id := m.retrySeq
	if retry, scheduled := m.retrying[ns]; scheduled {
		retry.work = mergeIndexWork(retry.work, work)
		m.retrying[ns] = retry
		m.queueMu.Unlock()
		return
	}
	m.retrying[ns] = indexRetry{id: id, work: work}
	m.queueMu.Unlock()

	m.retryWG.Add(1)
	go func() {
		defer m.retryWG.Done()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			m.cancelIndexRetry(ns)
		case <-timer.C:
			m.queueMu.Lock()
			retry, exists := m.retrying[ns]
			if exists && retry.id == id {
				delete(m.retrying, ns)
			}
			m.queueMu.Unlock()
			if exists && retry.id == id {
				m.enqueueWork(ns, retry.work)
			}
		}
	}()
}

func (m *Manager) cancelIndexRetry(ns indexNamespace) {
	m.queueMu.Lock()
	delete(m.retrying, ns)
	m.queueMu.Unlock()
}

func (m *Manager) enqueueExisting(ctx context.Context) {
	repositoryRoot, err := m.pathFor(m.repo, false)
	if err != nil {
		m.log.Error("locate package repository for index recovery", "error", err)
		return
	}
	err = filepath.WalkDir(repositoryRoot, func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			if strings.HasPrefix(entry.Name(), ".index-snapshot-") {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		relative, err := filepath.Rel(repositoryRoot, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if strings.HasSuffix(entry.Name(), ".apk") {
			arch, _, ok := repository.ParsePackagePath(relative)
			if !ok {
				return nil
			}
			m.enqueueIndex(indexNamespace{arch: arch})
			return nil
		}
		if entry.Name() == m.indexName {
			arch, ok := repository.ParseIndexPath(relative, m.indexName)
			if ok {
				m.enqueueIndex(indexNamespace{arch: arch})
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) && ctx.Err() == nil {
		m.log.Error("scan package repository for index recovery", "error", err)
	}
}

func (m *Manager) buildAndPublishIndex(ctx context.Context, ns indexNamespace, work indexWork) (published bool, retErr error) {
	packagePath, err := m.pathFor(path.Join(m.repo, ns.arch, "placeholder.apk"), true)
	if err != nil {
		return false, err
	}
	packageDir := filepath.Dir(packagePath)
	indexPath, err := m.pathFor(path.Join(m.repo, ns.arch, m.indexName), true)
	if err != nil {
		return false, err
	}

	fullRebuild := work.full
	if !fullRebuild {
		info, err := os.Lstat(indexPath)
		if errors.Is(err, os.ErrNotExist) {
			fullRebuild = true
		} else if err != nil {
			return false, err
		} else if !info.Mode().IsRegular() {
			return false, errors.New("index target is not a regular file")
		}
	}

	state := m.namespaceState(ns)
	state.mu.RLock()
	version := state.version
	var packageNames []string
	if fullRebuild {
		entries, err := os.ReadDir(packageDir)
		if errors.Is(err, os.ErrNotExist) {
			entries, err = nil, nil
		}
		if err != nil {
			state.mu.RUnlock()
			return false, err
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".apk") {
				packageNames = append(packageNames, entry.Name())
			}
		}
	} else {
		packageNames = make([]string, 0, len(work.additions))
		for filename := range work.additions {
			if path.Base(filename) != filename || !repository.ValidSegment(filename) || !strings.HasSuffix(filename, ".apk") {
				state.mu.RUnlock()
				return false, fmt.Errorf("invalid package filename %q in index work", filename)
			}
			packageNames = append(packageNames, filename)
		}
		sort.Strings(packageNames)
	}
	snapshotRoot, err := os.MkdirTemp(packageDir, ".index-snapshot-*")
	if err != nil {
		state.mu.RUnlock()
		return false, err
	}
	snapshotDir := filepath.Join(snapshotRoot, "packages")
	if err := os.Mkdir(snapshotDir, 0700); err != nil {
		cleanupErr := removeIndexSnapshot(snapshotRoot)
		state.mu.RUnlock()
		return false, errors.Join(err, cleanupErr)
	}
	packageCount := 0
	for _, filename := range packageNames {
		source := filepath.Join(packageDir, filename)
		info, err := os.Lstat(source)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			cleanupErr := removeIndexSnapshot(snapshotRoot)
			state.mu.RUnlock()
			return false, errors.Join(err, cleanupErr)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		snapshot := filepath.Join(snapshotDir, filename)
		if err := os.Link(source, snapshot); err != nil {
			cleanupErr := removeIndexSnapshot(snapshotRoot)
			state.mu.RUnlock()
			return false, errors.Join(fmt.Errorf("snapshot package %s: %w", filename, err), cleanupErr)
		}
		packageCount++
	}
	state.mu.RUnlock()
	defer func() {
		retErr = errors.Join(retErr, removeIndexSnapshot(snapshotRoot))
	}()

	if packageCount == 0 {
		if !fullRebuild {
			return true, nil
		}
		state.mu.RLock()
		if state.version != version {
			state.mu.RUnlock()
			return false, nil
		}
		if m.signingKey == nil {
			if empty, err := isEmptyAPKIndex(indexPath); err == nil && empty {
				state.mu.RUnlock()
				return true, nil
			}
			state.mu.RUnlock()
			err := os.Remove(indexPath)
			if errors.Is(err, os.ErrNotExist) {
				return true, nil
			}
			return true, err
		}
		state.mu.RUnlock()
	}

	outputFile, err := os.CreateTemp(filepath.Dir(indexPath), ".index-output-*")
	if err != nil {
		return false, err
	}
	outputPath := outputFile.Name()
	if err := outputFile.Close(); err != nil {
		return false, errors.Join(
			fmt.Errorf("close temporary APK index output: %w", err),
			removeIndexTempFile(outputPath),
		)
	}
	if err := os.Remove(outputPath); err != nil {
		return false, errors.Join(
			fmt.Errorf("remove temporary APK index output: %w", err),
			removeIndexTempFile(outputPath),
		)
	}
	defer func() {
		retErr = errors.Join(retErr, removeIndexTempFile(outputPath))
		retErr = errors.Join(retErr, removeIndexTempFile(outputPath+".tmp"))
	}()

	if fullRebuild {
		err = m.indexer.BuildV2Merge(ctx, snapshotDir, "", outputPath, ns.arch)
	} else {
		err = m.indexer.BuildV2Merge(ctx, snapshotDir, indexPath, outputPath, ns.arch)
	}
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.version != version {
		return false, nil
	}
	if err := os.Rename(outputPath, indexPath); err != nil {
		return false, err
	}
	return true, nil
}

func removeIndexSnapshot(root string) error {
	if err := os.RemoveAll(root); err != nil {
		return fmt.Errorf("remove index snapshot %s: %w", root, err)
	}
	return nil
}

func removeIndexTempFile(filename string) error {
	if err := os.Remove(filename); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove temporary index file %s: %w", filename, err)
	}
	return nil
}
