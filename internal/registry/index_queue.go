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
}

type indexRetry struct {
	id   uint64
	work indexWork
}

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
	m.enqueueWork(ns, indexWork{additions: map[string]struct{}{filename: {}}})
}

func (m *Manager) enqueueWork(ns indexNamespace, work indexWork) {
	m.queueMu.Lock()
	m.pending[ns] = mergeIndexWork(m.pending[ns], work)
	m.queueMu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func mergeIndexWork(first, second indexWork) indexWork {
	if first.full || second.full {
		return indexWork{full: true}
	}
	if len(first.additions)+len(second.additions) == 0 {
		return indexWork{}
	}
	merged := indexWork{additions: make(map[string]struct{}, len(first.additions)+len(second.additions))}
	for filename := range first.additions {
		merged.additions[filename] = struct{}{}
	}
	for filename := range second.additions {
		merged.additions[filename] = struct{}{}
	}
	return merged
}

func (m *Manager) nextIndex() (indexNamespace, indexWork, bool) {
	m.queueMu.Lock()
	defer m.queueMu.Unlock()
	for ns, work := range m.pending {
		delete(m.pending, ns)
		return ns, work, true
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
			ns, work, ok := m.nextIndex()
			if !ok {
				break
			}
			published, err := m.buildAndPublishIndex(ctx, ns, work)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				m.log.Error("package index generation failed", "repository", m.repo, "architecture", ns.arch, "error", err)
				m.retryIndex(ctx, ns, indexWork{full: true})
				continue
			}
			if !published {
				m.enqueueIndex(ns)
				continue
			}
			m.cancelIndexRetry(ns)
		}
	}
}

func (m *Manager) retryIndex(ctx context.Context, ns indexNamespace, work indexWork) {
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

	go func() {
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

func (m *Manager) buildAndPublishIndex(ctx context.Context, ns indexNamespace, work indexWork) (bool, error) {
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
		state.mu.RUnlock()
		os.RemoveAll(snapshotRoot)
		return false, err
	}
	packageCount := 0
	for _, filename := range packageNames {
		source := filepath.Join(packageDir, filename)
		info, err := os.Lstat(source)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			state.mu.RUnlock()
			os.RemoveAll(snapshotRoot)
			return false, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		snapshot := filepath.Join(snapshotDir, filename)
		if err := os.Link(source, snapshot); err != nil {
			state.mu.RUnlock()
			os.RemoveAll(snapshotRoot)
			return false, fmt.Errorf("snapshot package %s: %w", filename, err)
		}
		packageCount++
	}
	state.mu.RUnlock()
	defer os.RemoveAll(snapshotRoot)

	if packageCount == 0 {
		if !fullRebuild {
			return true, nil
		}
		state.mu.RLock()
		defer state.mu.RUnlock()
		if state.version != version {
			return false, nil
		}
		if empty, err := isEmptyAPKIndex(indexPath); err == nil && empty {
			return true, nil
		}
		err := os.Remove(indexPath)
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return true, err
	}

	outputFile, err := os.CreateTemp(filepath.Dir(indexPath), ".index-output-*")
	if err != nil {
		return false, err
	}
	outputPath := outputFile.Name()
	if err := outputFile.Close(); err != nil {
		os.Remove(outputPath)
		return false, err
	}
	if err := os.Remove(outputPath); err != nil {
		return false, err
	}
	defer os.Remove(outputPath)
	defer os.Remove(outputPath + ".tmp")

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
