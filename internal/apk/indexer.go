package apk

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type Indexer struct{ APKBinary, SigningKey string }

// BuildV2Merge merges the authoritative package set into an existing v2 index.
// The existing index is intentionally retained as the merge base for normal
// additions. Full rebuild callers pass an empty existing path.
func (i Indexer) BuildV2Merge(ctx context.Context, packageDir, existing, output, arch string) error {
	files, err := filepath.Glob(filepath.Join(packageDir, "*.apk"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no apk files in %s", packageDir)
	}
	return i.run(ctx, "index", "v2", packageDir, existing, output, arch, files)
}

// BuildV3 creates a Packages.adb index. apk-tools documents mkndx as the
// repository-index generator for v3; unlike v2 there is no merge operation,
// so deletions and additions both rebuild the authoritative package set.
func (i Indexer) BuildV3(ctx context.Context, packageDir, output, arch string) error {
	files, err := filepath.Glob(filepath.Join(packageDir, "*.apk"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no apk files in %s", packageDir)
	}
	tmp := output + ".tmp"
	_ = os.Remove(tmp)
	args := []string{"mkndx", "--output", tmp}
	if i.SigningKey != "" {
		args = append(args, "--sign-key", i.SigningKey)
	}
	args = append(args, files...)
	cmd := exec.CommandContext(ctx, i.APKBinary, args...)
	cmd.Dir = packageDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("apk mkndx: %w: %s", err, string(out))
	}
	if _, err := os.Stat(tmp); err != nil {
		return fmt.Errorf("v3 index not produced: %w", err)
	}
	if err := os.Rename(tmp, output); err != nil {
		return fmt.Errorf("publish v3 index: %w", err)
	}
	return nil
}

func (i Indexer) run(ctx context.Context, subcommand, format, dir, existing, output, arch string, files []string) error {
	tmp := output + ".tmp"
	_ = os.Remove(tmp)
	args := []string{subcommand, "--rewrite-arch", arch, "--output", tmp}
	if existing != "" {
		args = append(args, "--merge", "--index", existing)
	}
	if i.SigningKey != "" {
		args = append(args, "--sign-key", i.SigningKey)
	}
	args = append(args, files...)
	cmd := exec.CommandContext(ctx, i.APKBinary, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("apk index %s: %w: %s", format, err, string(out))
	}
	if _, err := os.Stat(tmp); err != nil {
		return fmt.Errorf("index not produced: %w", err)
	}
	if err := os.Rename(tmp, output); err != nil {
		return fmt.Errorf("publish index: %w", err)
	}
	return nil
}
