package repository

import "strings"

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
