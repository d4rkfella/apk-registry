package apk

import (
	"context"
	"fmt"

	"chainguard.dev/melange/pkg/index"
)

type Indexer struct{ SigningKey string }

// BuildV2Merge merges package files into an existing APKINDEX when provided.
func (i Indexer) BuildV2Merge(ctx context.Context, packageDir, existing, output, arch string) error {
	options := []index.Option{
		index.WithPackageDir(packageDir),
		index.WithIndexFile(output),
		index.WithExpectedArch(arch),
	}
	if existing != "" {
		options = append(options,
			index.WithSourceIndexFile(existing),
			index.WithMergeIndexFileFlag(true),
		)
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
