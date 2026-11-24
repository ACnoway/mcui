package xrayconfig

// StatisticsSocket is the private endpoint created by the managed Xray unit.
const StatisticsSocket = "/run/mcui-xray-stats/traffic.sock"

func enableStatistics(config map[string]any) {
	config["api"] = map[string]any{
		"tag": "@mcui-stats", "listen": StatisticsSocket + ",0660", "services": []string{"StatsService"},
	}
	config["stats"] = map[string]any{}
	config["policy"] = map[string]any{
		"levels": map[string]any{"0": map[string]bool{"statsUserUplink": true, "statsUserDownlink": true}},
		"system": map[string]bool{
			"statsInboundUplink": true, "statsInboundDownlink": true,
			"statsOutboundUplink": true, "statsOutboundDownlink": true,
		},
	}
}
