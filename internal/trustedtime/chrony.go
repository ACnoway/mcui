// Package trustedtime reads the system clock only while chrony reports a
// synchronized, authenticated NTS source selected from local configuration.
package trustedtime

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const DefaultNTSSource = "time.cloudflare.com"
const chronyCommandSocket = "/run/chrony/chronyd.sock"

var ErrUntrusted = errors.New("authenticated time source is unavailable")

type commandRunner func(context.Context, string, ...string) ([]byte, error)

// Chrony requires a selected and recently measured NTS source. It does not
// accept unauthenticated fallback sources as evidence that the local clock is
// trusted.
type Chrony struct {
	source      string
	commandHost string
	run         commandRunner
	now         func() time.Time
}

func NewChrony(source string) *Chrony {
	return newChrony(source, "127.0.0.1")
}

// NewChronyUnix is for local tools run by an operator already authorized to
// access the chrony command socket. Some releases only expose authdata there.
func NewChronyUnix(source string) *Chrony {
	return newChrony(source, chronyCommandSocket)
}

func newChrony(source, commandHost string) *Chrony {
	if source == "" {
		source = DefaultNTSSource
	}
	return &Chrony{
		source: source, commandHost: commandHost,
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, "/usr/bin/chronyc", args...).Output()
		},
		now: time.Now,
	}
}

// Now returns the local system time only after verifying chrony's selected
// source, NTS authentication state, synchronization status, and sample age.
func (c *Chrony) Now() (time.Time, error) {
	if c == nil || c.source == "" || c.commandHost == "" || c.run == nil || c.now == nil {
		return time.Time{}, ErrUntrusted
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sources, err := c.run(ctx, "chronyc", "-h", c.commandHost, "-N", "sources")
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: chronyc sources query failed: %v", ErrUntrusted, err)
	}
	if !selectedSourceFresh(string(sources), c.source) {
		return time.Time{}, fmt.Errorf("%w: configured source is not selected or its sample is stale", ErrUntrusted)
	}
	auth, err := c.run(ctx, "chronyc", "-h", c.commandHost, "-N", "authdata")
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: chronyc authdata query failed: %v", ErrUntrusted, err)
	}
	if !sourceAuthenticated(string(auth), c.source) {
		return time.Time{}, fmt.Errorf("%w: NTS authentication is unavailable", ErrUntrusted)
	}
	tracking, err := c.run(ctx, "chronyc", "-h", c.commandHost, "-N", "tracking")
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: chronyc tracking query failed: %v", ErrUntrusted, err)
	}
	if !trackingHealthy(string(tracking)) {
		return time.Time{}, fmt.Errorf("%w: chrony tracking is not within the allowed bounds", ErrUntrusted)
	}
	now := c.now().UTC()
	if now.IsZero() {
		return time.Time{}, ErrUntrusted
	}
	return now, nil
}

func (c *Chrony) Healthy() bool {
	_, err := c.Now()
	return err == nil
}

func selectedSourceFresh(output, expected string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || !strings.HasPrefix(fields[0], "^") || !strings.Contains(fields[0], "*") || fields[1] != expected {
			continue
		}
		reach, reachErr := strconv.ParseInt(fields[4], 8, 64)
		if reachErr != nil || reach == 0 {
			return false
		}
		age, err := parseDurationSeconds(fields[5])
		return err == nil && isFinite(age) && age >= 0 && age <= 300
	}
	return false
}

func sourceAuthenticated(output, expected string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[0] != expected || fields[1] != "NTS" {
			continue
		}
		_, keyErr := strconv.ParseUint(fields[2], 10, 64)
		aead, aeadErr := strconv.Atoi(fields[3])
		cookies, cookiesErr := strconv.Atoi(fields[8])
		cookieLength, lengthErr := strconv.Atoi(fields[9])
		return keyErr == nil && aeadErr == nil && (aead == 15 || aead == 30) && fields[7] == "0" && cookiesErr == nil && cookies > 0 && lengthErr == nil && cookieLength > 0
	}
	return false
}

func trackingHealthy(output string) bool {
	fields := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if ok {
			fields[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	if fields["Leap status"] != "Normal" {
		return false
	}
	systemOffset, err := firstNumber(fields["System time"])
	if err != nil || !isFinite(systemOffset) || absFloat(systemOffset) > 1 {
		return false
	}
	update, err := firstNumber(fields["Update interval"])
	if err != nil || !isFinite(update) || update < 0 || update > 300 {
		return false
	}
	dispersion, err := firstNumber(fields["Root dispersion"])
	if err != nil || !isFinite(dispersion) || dispersion < 0 || dispersion > 1 {
		return false
	}
	delay, err := firstNumber(fields["Root delay"])
	return err == nil && isFinite(delay) && delay >= 0 && absFloat(systemOffset)+dispersion+(0.5*delay) <= 1
}

func parseDurationSeconds(value string) (float64, error) {
	if value == "-" || value == "" {
		return 0, fmt.Errorf("missing sample age")
	}
	unit := value[len(value)-1]
	multiplier := 1.0
	switch unit {
	case 's':
		value = value[:len(value)-1]
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		// chronyc normally prints LastRx in seconds without a unit suffix.
	case 'm':
		value, multiplier = value[:len(value)-1], 60
	case 'h':
		value, multiplier = value[:len(value)-1], 3600
	case 'd':
		value, multiplier = value[:len(value)-1], 86400
	case 'y':
		value, multiplier = value[:len(value)-1], 365*86400
	default:
		return 0, fmt.Errorf("invalid sample age")
	}
	n, err := strconv.ParseFloat(value, 64)
	return n * multiplier, err
}

func absFloat(value float64) float64 {
	if value < 0 {
		return -value
	}
	return value
}

func isFinite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}

func firstNumber(value string) (float64, error) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0, fmt.Errorf("missing numeric value")
	}
	return strconv.ParseFloat(fields[0], 64)
}
