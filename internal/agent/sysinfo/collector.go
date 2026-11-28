package sysinfo

import (
	"context"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ACnoway/mcui/pkg/proto"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
)

type Collector struct {
	mu          sync.Mutex
	lastSample  time.Time
	lastBytesUp uint64
	lastBytesDn uint64
	publicIPv4  string
	publicIPv6  string
	ipFetchedAt time.Time
}

func NewCollector() *Collector {
	return &Collector{}
}

func (c *Collector) Collect(ctx context.Context) proto.SystemMetrics {
	hostname, _ := os.Hostname()
	cores, _ := cpu.Counts(true)
	pcts, _ := cpu.PercentWithContext(ctx, 0, false)
	var cpuPct float64
	if len(pcts) > 0 {
		cpuPct = pcts[0]
	}

	var memUsed, memTotal uint64
	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil && vm != nil {
		memUsed = vm.Used
		memTotal = vm.Total
	}

	var diskUsed, diskTotal uint64
	rootPath := "/"
	if runtime.GOOS == "windows" {
		rootPath = "C:\\"
	}
	if du, err := disk.UsageWithContext(ctx, rootPath); err == nil && du != nil {
		diskUsed = du.Used
		diskTotal = du.Total
	}

	uptime, _ := host.UptimeWithContext(ctx)

	var totalUp, totalDown, rateUp, rateDown uint64
	if counters, err := gnet.IOCountersWithContext(ctx, false); err == nil && len(counters) > 0 {
		totalUp = counters[0].BytesSent
		totalDown = counters[0].BytesRecv
		now := time.Now()

		c.mu.Lock()
		if !c.lastSample.IsZero() {
			elapsed := now.Sub(c.lastSample).Seconds()
			if elapsed > 0.2 {
				if totalUp >= c.lastBytesUp {
					rateUp = uint64(float64(totalUp-c.lastBytesUp) / elapsed)
				}
				if totalDown >= c.lastBytesDn {
					rateDown = uint64(float64(totalDown-c.lastBytesDn) / elapsed)
				}
			}
		}
		c.lastSample = now
		c.lastBytesUp = totalUp
		c.lastBytesDn = totalDown
		c.mu.Unlock()
	}

	ipv4, ipv6 := c.resolvePublicIPs(ctx)

	return proto.SystemMetrics{
		Hostname:     hostname,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		PublicIPv4:   ipv4,
		PublicIPv6:   ipv6,
		CPUPercent:   cpuPct,
		CPUCores:     cores,
		MemUsed:      memUsed,
		MemTotal:     memTotal,
		DiskUsed:     diskUsed,
		DiskTotal:    diskTotal,
		NetUpRate:    rateUp,
		NetDownRate:  rateDown,
		NetUpTotal:   totalUp,
		NetDownTotal: totalDown,
		Uptime:       uptime,
	}
}

func (c *Collector) resolvePublicIPs(ctx context.Context) (string, string) {
	c.mu.Lock()
	if time.Since(c.ipFetchedAt) < 10*time.Minute && (c.publicIPv4 != "" || c.publicIPv6 != "") {
		v4, v6 := c.publicIPv4, c.publicIPv6
		c.mu.Unlock()
		return v4, v6
	}
	c.mu.Unlock()

	v4 := probeIP(ctx, "https://api4.ipify.org")
	v6 := probeIP(ctx, "https://api6.ipify.org")

	c.mu.Lock()
	c.ipFetchedAt = time.Now()
	if v4 != "" {
		c.publicIPv4 = v4
	}
	if v6 != "" {
		c.publicIPv6 = v6
	}
	v4, v6 = c.publicIPv4, c.publicIPv6
	c.mu.Unlock()
	return v4, v6
}

func probeIP(parent context.Context, endpoint string) string {
	ctx, cancel := context.WithTimeout(parent, 2500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}
