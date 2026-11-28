package core

import (
	"context"
	"fmt"
	"sync"

	"github.com/ACnoway/mcui/pkg/proto"
)

type Manager struct {
	mu      sync.RWMutex
	drivers map[proto.CoreType]Driver
}

func NewManager(drivers ...Driver) *Manager {
	m := &Manager{drivers: make(map[proto.CoreType]Driver, len(drivers))}
	for _, d := range drivers {
		m.drivers[d.Type()] = d
	}
	return m
}

func (m *Manager) Get(t proto.CoreType) (Driver, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.drivers[t]
	if !ok {
		return nil, fmt.Errorf("unsupported core type %q", t)
	}
	return d, nil
}

func (m *Manager) AllStatuses() []proto.CoreStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]proto.CoreStatus, 0, len(m.drivers))
	for _, d := range m.drivers {
		out = append(out, d.Status())
	}
	return out
}

func (m *Manager) CollectAllTraffic(ctx context.Context) (map[string]proto.TrafficCounter, map[string]proto.TrafficCounter) {
	m.mu.RLock()
	drivers := make([]Driver, 0, len(m.drivers))
	for _, d := range m.drivers {
		drivers = append(drivers, d)
	}
	m.mu.RUnlock()

	mergedUsers := make(map[string]proto.TrafficCounter)
	mergedInbounds := make(map[string]proto.TrafficCounter)
	for _, d := range drivers {
		st := d.Status()
		if st.State != proto.CoreRunning {
			continue
		}
		u, ib, err := d.CollectTraffic(ctx)
		if err != nil {
			continue
		}
		for k, v := range u {
			cur := mergedUsers[k]
			cur.Up += v.Up
			cur.Down += v.Down
			mergedUsers[k] = cur
		}
		for k, v := range ib {
			cur := mergedInbounds[k]
			cur.Up += v.Up
			cur.Down += v.Down
			mergedInbounds[k] = cur
		}
	}
	return mergedUsers, mergedInbounds
}

func (m *Manager) RestoreAll(ctx context.Context) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, d := range m.drivers {
		_ = d.RestoreLKG(ctx)
	}
}

func (m *Manager) StopAll(ctx context.Context) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, d := range m.drivers {
		_ = d.Stop(ctx)
	}
}
