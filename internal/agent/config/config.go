package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	MasterURL   string `json:"masterUrl"`
	EnrollToken string `json:"enrollToken,omitempty"`
	NodeID      uint   `json:"nodeId,omitempty"`
	NodeName    string `json:"nodeName,omitempty"`
	NodeToken   string `json:"nodeToken,omitempty"`
	DataDir     string `json:"dataDir"`
	InsecureTLS bool   `json:"insecureTls,omitempty"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse agent config: %w", err)
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "/var/lib/mcui-agent"
	}
	return &cfg, nil
}

func Save(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
