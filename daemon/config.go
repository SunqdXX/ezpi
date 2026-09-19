package main

import (
	"encoding/json"
	"os"
	"time"
)

var DefaultConfigPath = defaultConfigPath()

type Config struct {
	ListenPort     uint16   `json:"listen_port"`
	TargetPort     uint16   `json:"target_port"`
	FWMark         uint32   `json:"fwmark"`
	SkipInterfaces []string `json:"skip_interfaces"`

	Strategy string `json:"strategy"`

	Engine string `json:"engine"`

	DesyncMethod  string `json:"desync_method"`
	DesyncFakeTTL int    `json:"desync_fake_ttl"`
	DesyncFakeSNI string `json:"desync_fake_sni"`
	DesyncFooling string `json:"desync_fooling"`

	AutoTuneHosts []string `json:"autotune_hosts"`

	HandshakeTimeoutSec int `json:"handshake_timeout_sec"`
	DialTimeoutSec      int `json:"dial_timeout_sec"`

	ProbeTimeoutSec int `json:"probe_timeout_sec"`
	IdleTimeoutSec  int `json:"idle_timeout_sec"`
	Retries         int `json:"retries"`

	SelfTestHosts []string `json:"selftest_hosts"`
}

func DefaultConfig() *Config {
	return &Config{
		ListenPort:     8443,
		TargetPort:     443,
		FWMark:         0x455A5049,
		SkipInterfaces: defaultSkipInterfaces,
		Strategy:       "auto",
		Engine:         "auto",
		DesyncMethod:   "fakesplit",
		DesyncFakeTTL:  6,
		DesyncFakeSNI:  "www.google.com",
		DesyncFooling:  "badsum",

		HandshakeTimeoutSec: 5,
		DialTimeoutSec:      10,
		ProbeTimeoutSec:     2,
		IdleTimeoutSec:      180,
		Retries:             2,

		SelfTestHosts: []string{
			"www.roblox.com",
			"apis.roblox.com",
			"gateway.discord.gg",
		},
	}
}

func (c *Config) HandshakeTimeout() time.Duration {
	return time.Duration(c.HandshakeTimeoutSec) * time.Second
}
func (c *Config) DialTimeout() time.Duration {
	return time.Duration(c.DialTimeoutSec) * time.Second
}
func (c *Config) ProbeTimeout() time.Duration {
	return time.Duration(c.ProbeTimeoutSec) * time.Second
}
func (c *Config) IdleTimeout() time.Duration {
	return time.Duration(c.IdleTimeoutSec) * time.Second
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 8443
	}
	if cfg.TargetPort == 0 {
		cfg.TargetPort = 443
	}
	return cfg, nil
}
