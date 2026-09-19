package main

import "ezpi/engine"

type (
	Strategy  = engine.Strategy
	RelayOpts = engine.RelayOpts
	Resolver  = engine.Resolver
	DialFunc  = engine.DialFunc
)

const (
	recHandshake  = engine.RecHandshake
	hsClientHello = engine.HSClientHello
	recHeaderLen  = engine.RecHeaderLen
	maxRecord     = engine.MaxRecord
)

var (
	Strategies          = engine.Strategies
	StrategyByName      = engine.StrategyByName
	StrategyNames       = engine.StrategyNames
	NewResolver         = engine.NewResolver
	Relay               = engine.Relay
	DialTLSWithStrategy = engine.DialTLSWithStrategy
)
