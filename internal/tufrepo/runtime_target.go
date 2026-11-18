package tufrepo

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const runtimeLayout = "agent-helper-zip-v1"
const maxRuntimeBytes = 256 << 20

var runtimeVersion = regexp.MustCompile(`^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
var runtimeDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var runtimeReviewID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// RuntimeReview binds an audited pair built and released by MCUI.
type RuntimeReview struct {
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Length       int64  `json:"length"`
	SHA256       string `json:"sha256"`
	ReviewID     string `json:"review_id"`
}

type runtimeCustom struct {
	Schema       int    `json:"schema_version"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Layout       string `json:"layout"`
	Source       string `json:"source_id"`
	ReviewID     string `json:"review_id"`
}

func ReviewedRuntimeTarget(review RuntimeReview) (*metadata.TargetFiles, error) {
	if !runtimeVersion.MatchString(review.Version) || (review.Architecture != "amd64" && review.Architecture != "arm64") ||
		review.Length < 1 || review.Length > maxRuntimeBytes || !runtimeDigest.MatchString(review.SHA256) || !runtimeReviewID.MatchString(review.ReviewID) {
		return nil, errors.New("invalid reviewed runtime bundle")
	}
	digest, err := hex.DecodeString(review.SHA256)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(runtimeCustom{
		Schema: 1, Version: review.Version, Architecture: review.Architecture,
		Layout: runtimeLayout, Source: "github:ACnoway/mcui", ReviewID: review.ReviewID,
	})
	if err != nil {
		return nil, err
	}
	return &metadata.TargetFiles{
		Path:   "runtime/node/" + review.Version + "/linux/" + review.Architecture + "/mcui-runtime-linux-" + review.Architecture + ".zip",
		Length: review.Length, Hashes: metadata.Hashes{"sha256": digest}, Custom: (*json.RawMessage)(&raw),
	}, nil
}

func ValidateRuntimeTarget(path string, files *metadata.TargetFiles) error {
	if files == nil || files.Custom == nil || len(files.Hashes) != 1 {
		return errors.New("runtime target lacks reviewed metadata or SHA-256")
	}
	var custom runtimeCustom
	if err := json.Unmarshal(*files.Custom, &custom); err != nil {
		return err
	}
	expected, err := ReviewedRuntimeTarget(RuntimeReview{
		Version: custom.Version, Architecture: custom.Architecture, Length: files.Length,
		SHA256: hex.EncodeToString(files.Hashes["sha256"]), ReviewID: custom.ReviewID,
	})
	if err != nil || path != expected.Path {
		return errors.New("runtime target does not match reviewed version and architecture")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, *files.Custom); err != nil || !bytes.Equal(compact.Bytes(), *expected.Custom) {
		return errors.New("runtime target custom metadata differs from the reviewed schema")
	}
	return nil
}
