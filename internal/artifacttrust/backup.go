package artifacttrust

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/ACnoway/mcui/internal/security"
)

const BackupEndpoint = "/api/v1/helper/artifacts/xray"

type BackupRequest struct {
	Task    json.RawMessage `json:"task"`
	LeaseID string          `json:"lease_id"`
	Length  int64           `json:"length"`
}

type installLeaseKey struct{}

func WithInstallLease(ctx context.Context, task []byte, lease string) context.Context {
	return context.WithValue(ctx, installLeaseKey{}, BackupRequest{Task: bytes.Clone(task), LeaseID: lease})
}

type masterBackup struct {
	url  string
	http *http.Client
}

// ConfigureMasterBackup must be called before the client is used. The Helper
// and Agent use the exact signed task and its lease, never a node token or URL
// supplied by a task.
func (c *Client) ConfigureMasterBackup(masterURL, caPath string) error {
	origin, err := security.MasterOrigin(masterURL)
	if err != nil {
		return err
	}
	var ca []byte
	if caPath != "" {
		ca, err = os.ReadFile(caPath)
		if err != nil {
			return err
		}
	}
	httpClient, err := security.NewMasterHTTPClient(ca, artifactTimeout)
	if err != nil {
		return err
	}
	c.backup = &masterBackup{url: origin + BackupEndpoint, http: httpClient}
	return nil
}

func (b *masterBackup) open(ctx context.Context, target Target) (io.ReadCloser, error) {
	request, ok := ctx.Value(installLeaseKey{}).(BackupRequest)
	if !ok || b == nil || len(request.LeaseID) != 32 || len(request.Task) == 0 || target.Core != "xray" {
		return nil, ErrUnavailable
	}
	request.Length = target.Size
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	res, err := b.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: Master backup request failed", ErrDownload)
	}
	if res.StatusCode != http.StatusOK || res.ContentLength != target.Size {
		_ = res.Body.Close()
		return nil, fmt.Errorf("%w: Master did not provide the exact backup artifact", ErrDownload)
	}
	return res.Body, nil
}
