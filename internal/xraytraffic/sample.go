// Package xraytraffic describes non-resetting samples from a managed Xray core.
package xraytraffic

import (
	"strconv"
	"strings"

	"github.com/ACnoway/mcui/internal/xrayconfig"
)

const MaxBytes = 1<<53 - 1

type Bytes struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

type Sample struct {
	Revision int64            `json:"revision"`
	Epoch    string           `json:"epoch"`
	At       int64            `json:"at_ms"`
	Counters map[string]Bytes `json:"counters"`
}

func (s Sample) Valid() bool {
	if s.Revision <= 0 || s.Revision > MaxBytes || s.At <= 0 || !xrayconfig.ValidPlanDigest(s.Epoch) ||
		s.Counters == nil || len(s.Counters) > 24 {
		return false
	}
	for key, amount := range s.Counters {
		scope, name, _ := strings.Cut(key, ":")
		switch scope {
		case "inbound":
			port, err := strconv.Atoi(name)
			if err != nil || port < 1024 || port > 65535 || strconv.Itoa(port) != name {
				return false
			}
		case "user", "outbound":
			if !xrayconfig.ValidUsername(name) {
				return false
			}
		default:
			return false
		}
		if amount.Up < 0 || amount.Down < 0 || amount.Up > MaxBytes || amount.Down > MaxBytes {
			return false
		}
	}
	return true
}

func (s Sample) Matches(plan xrayconfig.Plan, network *xrayconfig.Network) bool {
	known := make(map[string]bool)
	for _, inbound := range plan {
		known["inbound:"+strconv.Itoa(inbound.Port)] = true
		for _, user := range inbound.Users {
			known["user:"+user] = true
		}
	}
	if network != nil {
		for _, outbound := range network.Outbounds {
			known["outbound:"+outbound.Tag] = true
		}
	}
	for key := range s.Counters {
		if !known[key] {
			return false
		}
	}
	return true
}

// Usage tracks the bytes observed in the current applied revision. A new
// process starts fresh counters and may have missed bytes from the old one.
type Usage struct {
	Last   Sample           `json:"last"`
	Totals map[string]Bytes `json:"totals"`
	HasGap bool             `json:"has_gap"`
}

func (u Usage) Observe(sample Sample) Usage {
	if sample.Revision < u.Last.Revision || sample.At <= u.Last.At {
		return u
	}
	if sample.Revision != u.Last.Revision {
		u = Usage{Totals: make(map[string]Bytes)}
	}
	sameEpoch := u.Last.Epoch == sample.Epoch
	u.HasGap = u.HasGap || (u.Last.Epoch != "" && !sameEpoch)
	if sameEpoch {
		for key, previous := range u.Last.Counters {
			current, exists := sample.Counters[key]
			if !exists || current.Up < previous.Up || current.Down < previous.Down {
				u.HasGap = true
				return u
			}
		}
	}
	for key, current := range sample.Counters {
		previous := Bytes{}
		if sameEpoch {
			previous = u.Last.Counters[key]
		}
		total := u.Totals[key]
		u.Totals[key] = Bytes{
			Up:   min(MaxBytes, total.Up+current.Up-previous.Up),
			Down: min(MaxBytes, total.Down+current.Down-previous.Down),
		}
	}
	u.Last = sample
	return u
}
