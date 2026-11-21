package corecatalog

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	stableXrayVersion = regexp.MustCompile(`^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
	xrayDigest        = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidXrayRelease recognizes the exact release selector accepted by the
// privileged Xray lifecycle.
func ValidXrayRelease(version, sha256 string) bool {
	return stableXrayVersion.MatchString(version) && xrayDigest.MatchString(sha256)
}

// CompareXrayVersions compares two validated stable Xray versions numerically.
func CompareXrayVersions(left, right string) int {
	first := strings.Split(left[1:], ".")
	second := strings.Split(right[1:], ".")
	for i := range first {
		a, _ := strconv.Atoi(first[i])
		b, _ := strconv.Atoi(second[i])
		if a != b {
			return a - b
		}
	}
	return 0
}
