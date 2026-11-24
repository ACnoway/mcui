package master

import (
	"context"
	"time"

	"github.com/ACnoway/mcui/internal/xraytraffic"
)

type xrayClientTraffic struct {
	xraytraffic.Bytes
	Observed int  `json:"observed"`
	Scopes   int  `json:"scopes"`
	HasGap   bool `json:"has_gap"`
}

func (s *Server) attachXrayClientTraffic(ctx context.Context, rows []xrayClientView, revisions map[string]int64, now time.Time) error {
	cache := make(map[string]xraytraffic.Usage)
	for i := range rows {
		row := &rows[i]
		traffic := xrayClientTraffic{}
		scopes := make(map[[2]string]bool)
		for _, binding := range row.Bindings {
			key := [2]string{binding.NodeID, binding.Credential}
			scopes[key] = scopes[key] || binding.Applied
		}
		traffic.Scopes = len(scopes)
		for scope, applied := range scopes {
			node, credential := scope[0], scope[1]
			revision := revisions[node]
			if !applied || revision == 0 {
				continue
			}
			usage, cached := cache[node]
			if !cached {
				var err error
				usage, err = s.store.XrayTraffic(ctx, node)
				if err != nil {
					return err
				}
				cache[node] = usage
			}
			amount, observed := usage.Totals["user:"+credential]
			if !observed || usage.Last.Revision != revision {
				continue
			}
			traffic.Observed++
			traffic.Up = min(xraytraffic.MaxBytes, traffic.Up+amount.Up)
			traffic.Down = min(xraytraffic.MaxBytes, traffic.Down+amount.Down)
			traffic.HasGap = traffic.HasGap || usage.HasGap || usage.Last.At < now.Add(-45*time.Second).UnixMilli()
		}
		if traffic.Observed > 0 {
			row.Traffic = &traffic
		}
	}
	return nil
}
