package main

import "net"

type Redirector interface {
	Start(cfg *Config) error

	Destination(c net.Conn) (string, error)

	Dialer(cfg *Config) *net.Dialer

	Status() string

	Stop() error
}
