package trustedtime

import (
	"context"
	"slices"
	"testing"
	"time"
)

func TestChronyUnixQueriesAuthenticatedStatus(t *testing.T) {
	clock := NewChronyUnix(DefaultNTSSource)
	now := time.Unix(1_800_000_000, 0).UTC()
	clock.now = func() time.Time { return now }
	replies := map[string]string{
		"sources":  "^* time.cloudflare.com 8 2 377 3 +6385ns[+7762ns] +/- 20us\n",
		"authdata": "time.cloudflare.com NTS 1 30 128 0 0 0 8 100\n",
		"tracking": "System time : 0.0001 seconds slow of NTP time\nRoot delay : 0.01 seconds\nRoot dispersion : 0.02 seconds\nUpdate interval : 4.0 seconds\nLeap status : Normal\n",
	}
	clock.run = func(_ context.Context, command string, args ...string) ([]byte, error) {
		if command != "chronyc" || len(args) != 4 || !slices.Equal(args[:3], []string{"-h", "/run/chrony/chronyd.sock", "-N"}) {
			t.Fatalf("unexpected chrony invocation: %s %v", command, args)
		}
		return []byte(replies[args[3]]), nil
	}
	got, err := clock.Now()
	if err != nil || !got.Equal(now) {
		t.Fatalf("authenticated time = %v, err = %v", got, err)
	}
}

func TestSelectedSourceFreshAcceptsChronyLastRxSeconds(t *testing.T) {
	output := "MS Name/IP address Stratum Poll Reach LastRx Last sample\n^* time.cloudflare.com 3 6 377 23 -10us[ -12us] +/- 1ms\n"
	if !selectedSourceFresh(output, DefaultNTSSource) {
		t.Fatal("expected selected source with recent sample to be accepted")
	}
}

func TestSelectedSourceFreshRejectsOldOrUnselectedSource(t *testing.T) {
	for _, output := range []string{
		"^* time.cloudflare.com 3 6 377 6m -10us[ -12us] +/- 1ms\n",
		"^* time.cloudflare.com 3 6 000 23 -10us[ -12us] +/- 1ms\n",
		"^+ time.cloudflare.com 3 6 377 23 -10us[ -12us] +/- 1ms\n",
		"^* other.example 3 6 377 23 -10us[ -12us] +/- 1ms\n",
	} {
		if selectedSourceFresh(output, DefaultNTSSource) {
			t.Fatalf("unexpectedly accepted source row %q", output)
		}
	}
}

func TestSourceAuthenticatedRequiresNTSAndCookies(t *testing.T) {
	valid := "time.cloudflare.com NTS 1 15 256 1 0 0 8 100\n"
	if !sourceAuthenticated(valid, DefaultNTSSource) {
		t.Fatal("expected NTS source with cookies to be authenticated")
	}
	for _, output := range []string{
		"time.cloudflare.com - 0 0 0 - 0 0 0 0\n",
		"time.cloudflare.com NTS 1 15 256 1 0 1 8 100\n",
		"time.cloudflare.com NTS 1 15 256 1 0 0 0 0\n",
	} {
		if sourceAuthenticated(output, DefaultNTSSource) {
			t.Fatalf("unexpectedly accepted auth row %q", output)
		}
	}
}

func TestTrackingHealthyChecksClockBoundAndSynchronization(t *testing.T) {
	valid := "System time : 0.0001 seconds slow of NTP time\nRoot delay : 0.01 seconds\nRoot dispersion : 0.02 seconds\nUpdate interval : 64.2 seconds\nLeap status : Normal\n"
	if !trackingHealthy(valid) {
		t.Fatal("expected synchronized clock within its error bound")
	}
	for _, tracking := range []string{
		"System time : 2 seconds fast of NTP time\nRoot delay : 0.01 seconds\nRoot dispersion : 0.02 seconds\nUpdate interval : 64 seconds\nLeap status : Normal\n",
		"System time : 0.1 seconds slow of NTP time\nRoot delay : 0.01 seconds\nRoot dispersion : 0.02 seconds\nUpdate interval : 600 seconds\nLeap status : Normal\n",
		"System time : 0.1 seconds slow of NTP time\nRoot delay : 0.01 seconds\nRoot dispersion : 0.02 seconds\nUpdate interval : 64 seconds\nLeap status : Not synchronised\n",
		"System time : 0.1 seconds slow of NTP time\nRoot delay : 0.01 seconds\nRoot dispersion : 0.02 seconds\nUpdate interval : NaN seconds\nLeap status : Normal\n",
	} {
		if trackingHealthy(tracking) {
			t.Fatalf("unexpectedly accepted tracking state %q", tracking)
		}
	}
}
