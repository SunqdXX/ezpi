//go:build linux

package main

func desyncSupported() bool { return true }

func startDesync(cfg *Config) (desyncStopper, error) {
	d := newDesyncRedirector(desyncConfigFrom(cfg))
	if err := d.Start(cfg); err != nil {
		return nil, err
	}
	return d, nil
}
