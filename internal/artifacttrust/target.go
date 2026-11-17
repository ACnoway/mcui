package artifacttrust

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/ACnoway/mcui/internal/corecatalog"
)

var reviewIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

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
