package core

import (
	"context"

	"github.com/ACnoway/mcui/pkg/proto"
)

// Driver abstracts a proxy core engine (Xray, sing-box, etc.) managed by the Agent.
type Driver interface {
	Type() proto.CoreType
	Status() proto.CoreStatus
	Install(ctx context.Context, req proto.InstallCoreRequest) error
	Uninstall(ctx context.Context) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Restart(ctx context.Context) error
	ApplyState(ctx context.Context, spec proto.DesiredCoreSpec) (proto.ApplyStateResponse, error)
	CollectTraffic(ctx context.Context) (users map[string]proto.TrafficCounter, inbounds map[string]proto.TrafficCounter, err error)
	RecentLogs(lines int) []string
	RestoreLKG(ctx context.Context) error
}
