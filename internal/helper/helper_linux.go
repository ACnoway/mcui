//go:build linux

// Package helper implements the Linux-only status authorization boundary.
// Its runtime permits only fixed, read-only systemd status queries.
package helper

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
	"golang.org/x/sys/unix"
)

var ErrReconciliation = errors.New("helper ledger requires reconciliation")
var ErrDenied = errors.New("helper authorization denied")

type TrustedKey struct {
	PublicKey ed25519.PublicKey
	Purpose   string
}

type StatusCheckpoint interface {
	AuthorizeStatus(ctx context.Context, raw []byte, leaseID string) (serverTime time.Time, previousSequence int64, err error)
}

type Config struct {
	NodeID     string
	AllowedUID uint32
	Keys       map[string]TrustedKey
	Now        func() time.Time
	// TrustedTimeHealthy must report the health of an independently monitored time source.
	TrustedTimeHealthy func() bool
	ReadStatus         func(unit string) (string, error)
	ReadStatusAt       func(unit string, observedAt time.Time) (string, error)
	Checkpoint         StatusCheckpoint
}
type Helper struct {
	dir *os.File
	cfg Config
	mu  sync.Mutex
}
type record struct {
	Hash    string `json:"hash"`
	TaskID  string `json:"task_id"`
	Result  string `json:"result"`
	Pending bool   `json:"pending"`
}
type ledger struct {
	Version       int       `json:"version"`
	Node          string    `json:"node"`
	Records       []record  `json:"records"`
	TimeHighWater time.Time `json:"time_high_water"`
}
type task struct {
	Node     string `json:"node_id"`
	ID       string `json:"task_id"`
	Sequence int64  `json:"sequence"`
	Key      string `json:"signing_key_id"`
	Issued   string `json:"issued_at"`
	Before   string `json:"not_before"`
	Expires  string `json:"expires_at"`
	Payload  struct {
		Core string `json:"core"`
	} `json:"payload"`
}

// Initialize creates a new ledger only for an explicitly provisioned identity.
// Never use it to recover a missing or rolled-back ledger.
func Initialize(path string, c Config) (*Helper, error) {
	h, e := openDir(path, c)
	if e != nil {
		return nil, e
	}
	f, e := h.open("ledger.json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if e != nil {
		h.Close()
		return nil, e
	}
	b, _ := json.Marshal(ledger{Version: 1, Node: c.NodeID, Records: []record{}})
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	if x := f.Close(); e == nil {
		e = x
	}
	if e == nil {
		e = h.dir.Sync()
	}
	if e != nil {
		h.Close()
		return nil, e
	}
	return h, nil
}

// Open never silently initializes missing state. External trusted checkpoints are
// required to detect rollback or loss; they are not implemented here.
func Open(path string, c Config) (*Helper, error) {
	h, e := openDir(path, c)
	if e != nil {
		return nil, e
	}
	if _, e = h.load(); e != nil {
		h.Close()
		return nil, e
	}
	return h, nil
}
func openDir(path string, c Config) (*Helper, error) {
	if os.Geteuid() != 0 || c.NodeID == "" || c.Now == nil || (c.ReadStatus == nil && c.ReadStatusAt == nil) || len(c.Keys) == 0 {
		return nil, ErrDenied
	}
	keys := make(map[string]TrustedKey, len(c.Keys))
	for id, k := range c.Keys {
		if id == "" || len(k.PublicKey) != ed25519.PublicKeySize {
			return nil, ErrDenied
		}
		k.PublicKey = append(ed25519.PublicKey(nil), k.PublicKey...)
		keys[id] = k
	}
	c.Keys = keys
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	e = unix.Fstat(fd, &st)
	if e != nil || st.Uid != 0 || st.Mode&0777 != 0700 {
		f.Close()
		return nil, ErrDenied
	}
	return &Helper{dir: f, cfg: c}, nil
}
func (h *Helper) Close() error { return h.dir.Close() }
func (h *Helper) open(name string, flags int, mode uint32) (*os.File, error) {
	fd, e := unix.Openat(int(h.dir.Fd()), name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
	if e != nil {
		return nil, e
	}
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 {
		unix.Close(fd)
		return nil, ErrDenied
	}
	return os.NewFile(uintptr(fd), name), nil
}
func (h *Helper) load() (ledger, error) {
	var l ledger
	f, e := h.open("ledger.json", unix.O_RDONLY, 0)
	if e != nil {
		return l, fmt.Errorf("%w: %v", ErrReconciliation, e)
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 16<<20+1))
	if e != nil || len(b) > 16<<20 || json.Unmarshal(b, &l) != nil || l.Version != 1 || l.Node != h.cfg.NodeID || l.Records == nil {
		return l, ErrReconciliation
	}
	seen := make(map[string]bool, len(l.Records))
	for _, r := range l.Records {
		decoded, err := hex.DecodeString(r.Hash)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != r.Hash || r.TaskID == "" || seen[r.TaskID] || len(r.Result) > 4096 || (r.Pending && r.Result != "") {
			return ledger{}, ErrReconciliation
		}
		seen[r.TaskID] = true
	}
	return l, nil
}
func (h *Helper) save(l ledger) error {
	b, e := json.Marshal(l)
	if e != nil || len(b) > 16<<20 {
		return ErrReconciliation
	}
	name := "ledger.tmp"
	_ = unix.Unlinkat(int(h.dir.Fd()), name, 0)
	f, e := h.open(name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	if x := f.Close(); e == nil {
		e = x
	}
	if e != nil {
		return e
	}
	if e = unix.Renameat(int(h.dir.Fd()), name, int(h.dir.Fd()), "ledger.json"); e != nil {
		return e
	}
	return h.dir.Sync()
}

// Execute authenticates the peer from the connected Unix socket, not request data.
func (h *Helper) Execute(conn *net.UnixConn, raw []byte, leaseIDs ...string) (string, error) {
	if conn == nil {
		return "", ErrDenied
	}
	rc, e := conn.SyscallConn()
	if e != nil {
		return "", e
	}
	var cred *unix.Ucred
	var ce error
	e = rc.Control(func(fd uintptr) { cred, ce = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if e != nil {
		return "", e
	}
	if ce != nil || cred == nil || cred.Uid != h.cfg.AllowedUID {
		return "", ErrDenied
	}
	if h.cfg.Checkpoint == nil || len(leaseIDs) != 1 || leaseIDs[0] == "" {
		return "", ErrReconciliation
	}
	serverTime, previousSequence, err := h.cfg.Checkpoint.AuthorizeStatus(context.Background(), append([]byte(nil), raw...), leaseIDs[0])
	if err != nil {
		return "", err
	}
	if serverTime.IsZero() {
		return "", ErrReconciliation
	}
	return h.executeUIDAt(cred.Uid, raw, serverTime, previousSequence, true)
}
func (h *Helper) executeUID(uid uint32, raw []byte) (string, error) {
	return h.executeUIDAt(uid, raw, time.Time{}, -1, false)
}

func (h *Helper) executeUIDAt(uid uint32, raw []byte, trustedNow time.Time, previousSequence int64, checkpointed bool) (string, error) {
	if uid != h.cfg.AllowedUID || len(raw) == 0 || len(raw) > 65536 {
		return "", ErrDenied
	}
	raw = append([]byte(nil), raw...)
	if _, e := protocol.CanonicalV2TaskBytes(raw); e != nil {
		return "", ErrDenied
	}
	var t task
	if json.Unmarshal(raw, &t) != nil {
		return "", ErrDenied
	}
	k, ok := h.cfg.Keys[t.Key]
	if !ok || k.Purpose != "task" || protocol.VerifyV2Task(raw, k.PublicKey) != nil || t.Node != h.cfg.NodeID {
		return "", ErrDenied
	}
	issued, e := time.Parse(time.RFC3339, t.Issued)
	if e != nil {
		return "", ErrDenied
	}
	before, e := time.Parse(time.RFC3339, t.Before)
	if e != nil {
		return "", ErrDenied
	}
	expires, e := time.Parse(time.RFC3339, t.Expires)
	if e != nil {
		return "", ErrDenied
	}
	unit := ""
	switch t.Payload.Core {
	case "xray":
		unit = "xray.service"
	case "sing-box":
		unit = "sing-box.service"
	case "mita":
		unit = "mita.service"
	default:
		return "", ErrDenied
	}
	if checkpointed && previousSequence != t.Sequence-1 {
		return "", ErrReconciliation
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if e = unix.Flock(int(h.dir.Fd()), unix.LOCK_EX); e != nil {
		return "", e
	}
	defer unix.Flock(int(h.dir.Fd()), unix.LOCK_UN)
	l, e := h.load()
	if e != nil {
		return "", e
	}
	if !checkpointed {
		if h.cfg.TrustedTimeHealthy == nil || !h.cfg.TrustedTimeHealthy() {
			return "", ErrReconciliation
		}
		trustedNow = h.cfg.Now()
	} else if h.cfg.TrustedTimeHealthy != nil && !h.cfg.TrustedTimeHealthy() {
		return "", ErrReconciliation
	}
	now := trustedNow.UTC()
	if now.IsZero() || (!l.TimeHighWater.IsZero() && now.Before(l.TimeHighWater)) {
		return "", ErrReconciliation
	}
	if now.After(l.TimeHighWater) {
		l.TimeHighWater = now
		if e = h.save(l); e != nil {
			return "", ErrReconciliation
		}
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	for i, r := range l.Records {
		if r.Pending && (!checkpointed || int64(i+1) != t.Sequence || r.TaskID != t.ID || r.Hash != hash) {
			return "", ErrReconciliation
		}
	}
	if checkpointed {
		if int64(len(l.Records)) > t.Sequence || (int64(len(l.Records)) == t.Sequence && (l.Records[len(l.Records)-1].TaskID != t.ID || l.Records[len(l.Records)-1].Hash != hash)) {
			return "", ErrReconciliation
		}
		for seq := int64(len(l.Records) + 1); seq <= previousSequence; seq++ {
			gapHash := sha256.Sum256([]byte(fmt.Sprintf("MCUI-STATUS-TERMINAL-GAP\n%s\n%d", h.cfg.NodeID, seq)))
			l.Records = append(l.Records, record{Hash: hex.EncodeToString(gapHash[:]), TaskID: fmt.Sprintf("terminal-sequence-%d", seq), Result: "terminal-on-master"})
		}
	}
	existingIndex := -1
	for i, r := range l.Records {
		if r.TaskID == t.ID || int64(i+1) == t.Sequence {
			if r.TaskID != t.ID || int64(i+1) != t.Sequence || r.Hash != hash {
				return "", ErrDenied
			}
			if !r.Pending {
				return r.Result, nil
			}
			existingIndex = i
			break
		}
	}
	if issued.After(now.Add(30*time.Second)) || now.Before(before) || !now.Before(expires) || (existingIndex < 0 && t.Sequence != int64(len(l.Records)+1)) {
		return "", ErrDenied
	}
	if existingIndex < 0 {
		l.Records = append(l.Records, record{Hash: hash, TaskID: t.ID, Pending: true})
		existingIndex = len(l.Records) - 1
		if e = h.save(l); e != nil {
			return "", e
		}
	}
	var result string
	if h.cfg.ReadStatusAt != nil {
		result, e = h.cfg.ReadStatusAt(unit, now)
	} else {
		result, e = h.cfg.ReadStatus(unit)
	}
	if e != nil || len(result) > 4096 {
		return "", ErrReconciliation
	}
	l.Records[existingIndex].Pending = false
	l.Records[existingIndex].Result = result
	if e = h.save(l); e != nil {
		return "", ErrReconciliation
	}
	return result, nil
}
