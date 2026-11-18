package repository

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

type APKMetadata struct{ Name, Version, Arch string }

func FilenameMatchesAPKMetadata(filename string, metadata APKMetadata) bool {
	base := strings.TrimSuffix(filename, ".apk")
	if idx := strings.LastIndex(base, "-r"); idx > 0 {
		before := base[:idx]
		if dash := strings.LastIndex(before, "-"); dash > 0 {
			return before[:dash] == metadata.Name && before[dash+1:]+base[idx:] == metadata.Version
		}
	}
	return base == metadata.Name && metadata.Version == "unknown"
}

func ParseAPKMetadata(r io.Reader) (APKMetadata, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return APKMetadata{}, fmt.Errorf("invalid apk gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var out APKMetadata
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, fmt.Errorf("invalid apk tar: %w", err)
		}
		if h.Name == ".PKGINFO" || strings.HasSuffix(h.Name, "/.PKGINFO") {
			b, err := io.ReadAll(io.LimitReader(tr, 1<<20))
			if err != nil {
				return out, err
			}
			for _, line := range strings.Split(string(b), "\n") {
				k, v, ok := strings.Cut(line, " = ")
				if !ok {
					continue
				}
				switch k {
				case "pkgname":
					out.Name = v
				case "pkgver":
					out.Version = v
				case "arch":
					out.Arch = v
				}
			}
			break
		}
	}
	if out.Name == "" || out.Version == "" || out.Arch == "" {
		return APKMetadata{}, fmt.Errorf("APK .PKGINFO is missing pkgname/pkgver/arch")
	}
	return out, nil
}
