package corecatalog

import "regexp"

var (
	stableXrayVersion = regexp.MustCompile(`^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
	xrayDigest        = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidXrayRelease recognizes the exact release selector accepted by the
// privileged Xray lifecycle.
func ValidXrayRelease(version, sha256 string) bool {
	return stableXrayVersion.MatchString(version) && xrayDigest.MatchString(sha256)
}
