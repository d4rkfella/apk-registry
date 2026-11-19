package repository

import (
	"regexp"
	"strings"

	"chainguard.dev/apko/pkg/build/types"
)

var filenameRE = regexp.MustCompile(`^[A-Za-z0-9._+~-]+\.apk$`)
var segmentRE = regexp.MustCompile(`^[A-Za-z0-9._+~-]+$`)
var melangeArchitectures = supportedMelangeArchitectures()

func ValidSegment(segment string) bool {
	return segment != "." && segment != ".." && segmentRE.MatchString(segment)
}

func SupportedArchitecture(arch string) bool {
	_, ok := melangeArchitectures[arch]
	return ok
}

func supportedMelangeArchitectures() map[string]struct{} {
	architectures := make(map[string]struct{}, len(types.AllArchs))
	for _, arch := range types.AllArchs {
		architectures[arch.ToAPK()] = struct{}{}
	}
	return architectures
}

func ParsePackagePath(relative string) (arch, filename string, ok bool) {
	parts := splitPath(relative)
	if len(parts) != 2 || !ValidSegment(parts[0]) || !filenameRE.MatchString(parts[1]) {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func ParseIndexPath(relative, indexName string) (arch string, ok bool) {
	parts := splitPath(relative)
	if len(parts) != 2 || !ValidSegment(parts[0]) || parts[1] != indexName {
		return "", false
	}
	return parts[0], true
}

func splitPath(relative string) []string {
	if strings.ContainsAny(relative, `\\`) {
		return nil
	}
	relative = strings.Trim(relative, "/")
	if relative == "" {
		return nil
	}
	parts := strings.Split(relative, "/")
	for _, part := range parts {
		if !ValidSegment(part) {
			return nil
		}
	}
	return parts
}
