package xray

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ACnoway/mcui/internal/agent/core"
	"github.com/ACnoway/mcui/pkg/proto"
)

var (
	userStatRe    = regexp.MustCompile(`^user>>>(.+)>>>traffic>>>(uplink|downlink)$`)
	inboundStatRe = regexp.MustCompile(`^inbound>>>(.+)>>>traffic>>>(uplink|downlink)$`)
)

type Driver struct {
	mu          sync.Mutex
	baseDir     string
	state       proto.CoreState
	version     string
	errorMsg    string
	progressPct int
	configHash  string
	apiPort     int
	cmd         *exec.Cmd
	stopCh      chan struct{}
	logs        *core.RingLog
}

func NewDriver(dataDir string) *Driver {
	d := &Driver{
		baseDir: filepath.Join(dataDir, "cores", "xray"),
		state:   proto.CoreUninstalled,
		logs:    core.NewRingLog(500),
	}
	d.refreshInstalledVersion()
	return d
}

func (d *Driver) Type() proto.CoreType { return proto.CoreXray }

func (d *Driver) binaryPath() string {
	name := "xray"
	if runtime.GOOS == "windows" {
		name = "xray.exe"
	}
	return filepath.Join(d.baseDir, name)
}

func (d *Driver) configPath() string    { return filepath.Join(d.baseDir, "config.json") }
func (d *Driver) lkgConfigPath() string { return filepath.Join(d.baseDir, "config.lkg.json") }

func (d *Driver) refreshInstalledVersion() {
	bin := d.binaryPath()
	if st, err := os.Stat(bin); err != nil || st.IsDir() {
		d.state = proto.CoreUninstalled
		d.version = ""
		return
	}
	ver := probeVersion(bin)
	d.version = ver
	if d.state == proto.CoreUninstalled {
		d.state = proto.CoreStopped
	}
}

func probeVersion(bin string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").CombinedOutput()
	if err != nil {
		return "unknown"
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if strings.EqualFold(f, "Xray") && i+1 < len(fields) {
			return "v" + strings.TrimPrefix(fields[i+1], "v")
		}
	}
	return "unknown"
}

func (d *Driver) Status() proto.CoreStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	installed := d.state != proto.CoreUninstalled && d.state != proto.CoreInstalling
	return proto.CoreStatus{
		CoreType:    proto.CoreXray,
		Installed:   installed,
		Version:     d.version,
		State:       d.state,
		ErrorMsg:    d.errorMsg,
		ProgressPct: d.progressPct,
		ConfigHash:  d.configHash,
	}
}

func (d *Driver) RecentLogs(lines int) []string {
	return d.logs.Tail(lines)
}

func (d *Driver) Install(ctx context.Context, req proto.InstallCoreRequest) error {
	d.mu.Lock()
	if d.state == proto.CoreInstalling {
		d.mu.Unlock()
		return errors.New("xray installation already in progress")
	}
	wasRunning := d.state == proto.CoreRunning
	prevState := d.state
	d.state = proto.CoreInstalling
	d.errorMsg = ""
	d.progressPct = 5
	d.mu.Unlock()

	fail := func(err error) error {
		d.mu.Lock()
		if prevState == proto.CoreUninstalled {
			d.state = proto.CoreUninstalled
		} else {
			d.state = proto.CoreError
		}
		d.errorMsg = err.Error()
		d.progressPct = 0
		d.mu.Unlock()
		return err
	}

	if err := os.MkdirAll(d.baseDir, 0o755); err != nil {
		return fail(err)
	}

	tmpZip := filepath.Join(d.baseDir, "xray-download.zip")
	defer os.Remove(tmpZip)

	if err := d.downloadArchive(ctx, req.ArchiveURL, tmpZip, req.SHA256); err != nil {
		return fail(err)
	}

	stagingDir := filepath.Join(d.baseDir, "staging")
	_ = os.RemoveAll(stagingDir)
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		return fail(err)
	}
	defer os.RemoveAll(stagingDir)

	if err := extractZip(tmpZip, stagingDir); err != nil {
		return fail(err)
	}

	binName := filepath.Base(d.binaryPath())
	stagedBin := filepath.Join(stagingDir, binName)
	if err := os.Chmod(stagedBin, 0o755); err != nil {
		return fail(fmt.Errorf("missing %s in archive: %w", binName, err))
	}
	ver := probeVersion(stagedBin)
	if ver == "unknown" {
		return fail(errors.New("downloaded xray binary failed smoke test"))
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if wasRunning {
		d.stopLocked()
	}

	for _, asset := range []string{binName, "geoip.dat", "geosite.dat"} {
		src := filepath.Join(stagingDir, asset)
		if _, err := os.Stat(src); err == nil {
			dst := filepath.Join(d.baseDir, asset)
			_ = os.Remove(dst)
			if err := os.Rename(src, dst); err != nil {
				return fmt.Errorf("install %s: %w", asset, err)
			}
		}
	}

	d.version = ver
	d.progressPct = 100
	d.errorMsg = ""
	d.state = proto.CoreStopped

	if wasRunning {
		if _, err := os.Stat(d.configPath()); err == nil {
			if err := d.startLocked(); err != nil {
				d.state = proto.CoreError
				d.errorMsg = err.Error()
				return err
			}
		}
	}
	return nil
}

func (d *Driver) downloadArchive(ctx context.Context, url, dest, expectedSHA256 string) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("download archive: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download archive HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	hasher := sha256.New()
	total := resp.ContentLength
	var written int64
	buf := make([]byte, 64*1024)

	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				return werr
			}
			hasher.Write(buf[:n])
			written += int64(n)
			if total > 0 {
				pct := 10 + int(float64(written)/float64(total)*80)
				d.mu.Lock()
				d.progressPct = pct
				d.mu.Unlock()
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}

	if expectedSHA256 != "" {
		got := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(got, expectedSHA256) {
			return fmt.Errorf("sha256 mismatch: got %s, want %s", got, expectedSHA256)
		}
	}
	return nil
}

func extractZip(zipPath, destDir string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		base := filepath.Base(f.Name)
		if base == "." || base == ".." {
			continue
		}
		target := filepath.Join(destDir, base)
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, io.LimitReader(rc, 256<<20))
		out.Close()
		rc.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}

func (d *Driver) Uninstall(_ context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopLocked()
	if err := os.RemoveAll(d.baseDir); err != nil {
		return err
	}
	d.state = proto.CoreUninstalled
	d.version = ""
	d.errorMsg = ""
	d.configHash = ""
	d.progressPct = 0
	return nil
}

func (d *Driver) Start(_ context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state == proto.CoreUninstalled {
		return errors.New("xray is not installed")
	}
	if d.state == proto.CoreRunning {
		return nil
	}
	return d.startLocked()
}

func (d *Driver) Stop(_ context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopLocked()
	if d.state != proto.CoreUninstalled {
		d.state = proto.CoreStopped
	}
	return nil
}

func (d *Driver) Restart(_ context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state == proto.CoreUninstalled {
		return errors.New("xray is not installed")
	}
	d.stopLocked()
	return d.startLocked()
}

func (d *Driver) ApplyState(ctx context.Context, spec proto.DesiredCoreSpec) (proto.ApplyStateResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.state == proto.CoreUninstalled || d.state == proto.CoreInstalling {
		return proto.ApplyStateResponse{}, errors.New("xray core is not installed on this node")
	}

	if len(spec.Inbounds) == 0 {
		d.stopLocked()
		_ = os.Remove(d.configPath())
		d.configHash = "empty"
		d.state = proto.CoreStopped
		d.errorMsg = ""
		return proto.ApplyStateResponse{Applied: true, ConfigHash: "empty"}, nil
	}

	if d.apiPort == 0 {
		port, err := pickFreeLocalPort()
		if err != nil {
			return proto.ApplyStateResponse{}, err
		}
		d.apiPort = port
	}

	rawCfg, hash, err := RenderConfig(spec, d.apiPort)
	if err != nil {
		return proto.ApplyStateResponse{}, err
	}

	if d.state == proto.CoreRunning && d.configHash == hash {
		return proto.ApplyStateResponse{Applied: true, HotApplied: true, ConfigHash: hash}, nil
	}

	if err := os.MkdirAll(d.baseDir, 0o755); err != nil {
		return proto.ApplyStateResponse{}, err
	}
	testCfgPath := d.configPath() + ".candidate"
	if err := os.WriteFile(testCfgPath, rawCfg, 0o600); err != nil {
		return proto.ApplyStateResponse{}, err
	}
	defer os.Remove(testCfgPath)

	if err := d.preflightTest(ctx, testCfgPath); err != nil {
		return proto.ApplyStateResponse{}, fmt.Errorf("xray config test failed: %w", err)
	}

	if err := os.WriteFile(d.configPath(), rawCfg, 0o600); err != nil {
		return proto.ApplyStateResponse{}, err
	}

	d.stopLocked()
	if err := d.startLocked(); err != nil {
		if lkg, lerr := os.ReadFile(d.lkgConfigPath()); lerr == nil {
			_ = os.WriteFile(d.configPath(), lkg, 0o600)
			_ = d.startLocked()
		}
		d.errorMsg = err.Error()
		return proto.ApplyStateResponse{}, err
	}

	_ = os.WriteFile(d.lkgConfigPath(), rawCfg, 0o600)
	d.configHash = hash
	d.errorMsg = ""
	return proto.ApplyStateResponse{Applied: true, ConfigHash: hash}, nil
}

func (d *Driver) RestoreLKG(_ context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state == proto.CoreUninstalled {
		return nil
	}
	if _, err := os.Stat(d.lkgConfigPath()); err != nil {
		return nil
	}
	raw, err := os.ReadFile(d.lkgConfigPath())
	if err != nil {
		return err
	}
	if err := os.WriteFile(d.configPath(), raw, 0o600); err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	d.configHash = hex.EncodeToString(sum[:16])
	return d.startLocked()
}

func (d *Driver) preflightTest(ctx context.Context, cfgPath string) error {
	tctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(tctx, d.binaryPath(), "run", "-test", "-config", cfgPath)
	cmd.Dir = d.baseDir
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+d.baseDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (d *Driver) startLocked() error {
	if _, err := os.Stat(d.configPath()); err != nil {
		return errors.New("no xray configuration has been applied yet")
	}
	cmd := exec.Command(d.binaryPath(), "run", "-config", d.configPath())
	cmd.Dir = d.baseDir
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+d.baseDir)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		d.state = proto.CoreError
		d.errorMsg = err.Error()
		return err
	}

	go d.logs.Capture(stdout)
	go d.logs.Capture(stderr)

	stopCh := make(chan struct{})
	exitedCh := make(chan error, 1)
	d.cmd = cmd
	d.stopCh = stopCh

	go func() {
		waitErr := cmd.Wait()
		exitedCh <- waitErr
		d.mu.Lock()
		defer d.mu.Unlock()
		select {
		case <-stopCh:
			return
		default:
			if d.cmd == cmd {
				d.state = proto.CoreError
				if waitErr != nil {
					d.errorMsg = waitErr.Error()
				} else {
					d.errorMsg = "xray exited unexpectedly"
				}
			}
		}
	}()

	select {
	case err := <-exitedCh:
		d.state = proto.CoreError
		if err != nil {
			return fmt.Errorf("xray exited on startup: %w", err)
		}
		return errors.New("xray exited immediately")
	case <-time.After(350 * time.Millisecond):
		d.state = proto.CoreRunning
		d.errorMsg = ""
		return nil
	}
}

func (d *Driver) stopLocked() {
	if d.stopCh != nil {
		close(d.stopCh)
		d.stopCh = nil
	}
	if d.cmd != nil && d.cmd.Process != nil {
		_ = d.cmd.Process.Kill()
		_, _ = d.cmd.Process.Wait()
	}
	d.cmd = nil
}

func (d *Driver) CollectTraffic(ctx context.Context) (map[string]proto.TrafficCounter, map[string]proto.TrafficCounter, error) {
	d.mu.Lock()
	running := d.state == proto.CoreRunning
	apiPort := d.apiPort
	bin := d.binaryPath()
	d.mu.Unlock()

	if !running || apiPort <= 0 {
		return nil, nil, nil
	}

	qctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	serverAddr := fmt.Sprintf("127.0.0.1:%d", apiPort)
	out, err := exec.CommandContext(qctx, bin, "api", "statsquery", "--server="+serverAddr, "-reset").Output()
	if err != nil {
		return nil, nil, err
	}

	return parseStatsQueryOutput(out)
}

type xrayStatsResponse struct {
	Stat []struct {
		Name  string      `json:"name"`
		Value jsonNumber  `json:"value"`
	} `json:"stat"`
}

type jsonNumber int64

func (n *jsonNumber) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" {
		*n = 0
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*n = jsonNumber(v)
	return nil
}

func parseStatsQueryOutput(raw []byte) (map[string]proto.TrafficCounter, map[string]proto.TrafficCounter, error) {
	users := make(map[string]proto.TrafficCounter)
	inbounds := make(map[string]proto.TrafficCounter)
	if len(strings.TrimSpace(string(raw))) == 0 {
		return users, inbounds, nil
	}

	// `xray api statsquery` emits JSON (`{"stat": [...]}`). Handle both JSON and line-oriented fallback.
	var parsed xrayStatsResponse
	if err := jsonUnmarshalRelaxed(raw, &parsed); err == nil && len(parsed.Stat) > 0 {
		for _, item := range parsed.Stat {
			val := int64(item.Value)
			if val <= 0 {
				continue
			}
			if m := userStatRe.FindStringSubmatch(item.Name); len(m) == 3 {
				c := users[m[1]]
				if m[2] == "uplink" {
					c.Up += val
				} else {
					c.Down += val
				}
				users[m[1]] = c
				continue
			}
			if m := inboundStatRe.FindStringSubmatch(item.Name); len(m) == 3 {
				if m[1] == "mcui-api" {
					continue
				}
				c := inbounds[m[1]]
				if m[2] == "uplink" {
					c.Up += val
				} else {
					c.Down += val
				}
				inbounds[m[1]] = c
			}
		}
	}
	return users, inbounds, nil
}

func pickFreeLocalPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}
