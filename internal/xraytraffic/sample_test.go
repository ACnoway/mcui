package xraytraffic

import (
	"strings"
	"testing"
)

func TestUsageRetriesRestartsAndRevisions(t *testing.T) {
	const key = "user:alice"
	first := Sample{Revision: 1, Epoch: strings.Repeat("a", 64), At: 100, Counters: map[string]Bytes{key: {Up: 15, Down: 20}}}
	if !first.Valid() {
		t.Fatal("valid sample was rejected")
	}
	usage := Usage{}.Observe(first).Observe(first)
	second := Sample{Revision: 1, Epoch: first.Epoch, At: 150, Counters: map[string]Bytes{key: {Up: 17, Down: 22}}}
	usage = usage.Observe(second)
	if usage.Totals[key] != second.Counters[key] || usage.HasGap {
		t.Fatalf("duplicate or cumulative sample counted incorrectly: %+v", usage)
	}
	reset := Sample{Revision: 1, Epoch: first.Epoch, At: 175, Counters: map[string]Bytes{key: {Up: 2, Down: 4}}}
	usage = usage.Observe(reset)
	if usage.Totals[key] != second.Counters[key] || !usage.HasGap {
		t.Fatalf("counter reset was not treated as a gap: %+v", usage)
	}
	reset.Epoch = strings.Repeat("b", 64)
	usage = usage.Observe(reset).Observe(first)
	if usage.Totals[key] != (Bytes{Up: 19, Down: 26}) || !usage.HasGap {
		t.Fatalf("new process or late sample counted incorrectly: %+v", usage)
	}
	reset.Revision++
	reset.At++
	usage = usage.Observe(reset)
	if usage.Totals[key] != reset.Counters[key] || usage.HasGap {
		t.Fatalf("prior revision leaked into a new revision: %+v", usage)
	}
}
