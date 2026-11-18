package artifacttrust

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

var reviewIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// CoreReview is the exact artifact record provided by an upstream release review.
type CoreReview struct {
	Core            string `json:"core"`
	Version         string `json:"version"`
	Architecture    string `json:"architecture"`
	Length          int64  `json:"length"`
	SHA256          string `json:"sha256"`
	ReviewID        string `json:"review_id"`
	SignatureStatus string `json:"upstream_signature_status"`
}

// ReviewedCoreTarget prepares the standard TUF entry for independent review
// and signing. The release metadata explicitly records the reviewer's findings.
func ReviewedCoreTarget(review CoreReview) (*metadata.TargetFiles, error) {
	filename, err := corecatalog.ExpectedAssetName(review.Core, review.Version, review.Architecture)
	if err != nil {
		return nil, err
	}
	digest, err := hex.DecodeString(review.SHA256)
	if err != nil || len(digest) != 32 || strings.ToLower(review.SHA256) != review.SHA256 ||
		review.Length <= 0 || review.Length > maxTargetBytes || review.SignatureStatus == "unverified" {
		return nil, errors.New("review requires an exact SHA-256, bounded length and resolved upstream signature status")
	}
	source, err := corecatalog.OfficialSourceID(review.Core)
	if err != nil {
		return nil, err
	}
	format := "deb"
	if review.Core == "xray" {
		format = "zip"
	}
	custom := targetCustom{
		SchemaVersion: 1, Core: review.Core, Version: review.Version, OS: "linux",
		Architecture: review.Architecture, BuildOptions: "upstream-prebuilt", ArchiveFormat: format,
		ArtifactID: artifactID(review.Core, review.Architecture, digest), SourceID: source,
		ReviewID: review.ReviewID, SignatureStatus: review.SignatureStatus,
	}
	if err := validateCustom(custom, review.Core, review.Version, review.Architecture, digest); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(custom)
	if err != nil {
		return nil, err
	}
	return &metadata.TargetFiles{
		Path:   "cores/" + review.Core + "/" + review.Version + "/linux/" + review.Architecture + "/" + filename,
		Length: review.Length, Hashes: metadata.Hashes{"sha256": metadata.HexBytes(digest)}, Custom: (*json.RawMessage)(&raw),
	}, nil
}

// ValidateReviewedCoreTarget checks a repository's signed Core target entry.
func ValidateReviewedCoreTarget(path string, files *metadata.TargetFiles) error {
	parts := strings.Split(path, "/")
	if len(parts) != 6 || parts[0] != "cores" || parts[3] != "linux" || files == nil {
		return ErrUntrustedTarget
	}
	filename, err := corecatalog.ExpectedAssetName(parts[1], parts[2], parts[4])
	if err != nil || filename != parts[5] {
		return ErrUntrustedTarget
	}
	entry := *files
	entry.Path = path
	target, err := (&Client{}).targetFromMetadata(&entry, parts[1], parts[2], parts[4], filename)
	if err != nil || target.SignatureStatus == "unverified" {
		return ErrUntrustedTarget
	}
	return nil
}

func validateCustom(custom targetCustom, core, version, arch string, digest []byte) error {
	if custom.SchemaVersion != 1 || custom.Core != core || custom.Version != version || custom.OS != "linux" || custom.Architecture != arch {
		return fmt.Errorf("%w: target platform binding does not match", ErrUntrustedTarget)
	}
	if custom.ArtifactID != artifactID(core, arch, digest) || !reviewIdentifier.MatchString(custom.ReviewID) {
		return fmt.Errorf("%w: artifact or review identifier does not match", ErrUntrustedTarget)
	}
	sourceID, err := corecatalog.OfficialSourceID(core)
	if err != nil || custom.SourceID != sourceID {
		return fmt.Errorf("%w: target source is not an approved fixed source", ErrUntrustedTarget)
	}
	if custom.BuildOptions != "upstream-prebuilt" {
		return fmt.Errorf("%w: build options must identify an upstream prebuilt artifact", ErrUntrustedTarget)
	}
	expectedFormat := "deb"
	if core == "xray" {
		expectedFormat = "zip"
	}
	if custom.ArchiveFormat != expectedFormat {
		return fmt.Errorf("%w: archive format does not match the fixed Core mapping", ErrUntrustedTarget)
	}
	switch custom.SignatureStatus {
	case "verified", "not-provided", "unverified":
	default:
		return fmt.Errorf("%w: upstream signature status is not recorded", ErrUntrustedTarget)
	}
	return nil
}

func artifactID(core, arch string, digest []byte) string {
	if len(digest) != 32 {
		return ""
	}
	return core + "-" + arch + "-" + hex.EncodeToString(digest)
}

func rejectDuplicateCustomFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return errors.New("custom metadata must be an object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return errors.New("custom metadata field name is invalid")
		}
		if _, duplicate := seen[name]; duplicate {
			return errors.New("duplicate custom metadata field")
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if err = decoder.Decode(&value); err != nil {
			return err
		}
	}
	if _, err = decoder.Token(); err != nil {
		return err
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("trailing custom metadata")
	}
	return nil
}
