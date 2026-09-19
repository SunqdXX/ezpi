//go:build linux

package main

import (
	"fmt"
	"os"

	"github.com/google/nftables"
)

const platformName = "linux/nftables"

const unitName = "ezpi.service"

func defaultConfigPath() string { return "/etc/ezpi/config.json" }

var defaultSkipInterfaces = []string{"lo", "proton0"}

func restoreSystem(cfg *Config) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root to remove nftables rules")
	}
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	conn.DelTable(&nftables.Table{Name: tableName, Family: nftables.TableFamilyIPv4})
	conn.Flush()
	return nil
}

func requirePrivilege() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root to manage nftables (try: systemctl start ezpi)")
	}
	return nil
}

var linuxMethod = "firewall redirect"

func storeMethodLinux(m string) {
	if m == "" {
		linuxMethod = "firewall redirect"
		return
	}
	linuxMethod = m
}

func activeMethod() string { return linuxMethod }

func preferDesyncEngine(cfg *Config) bool { return false }
