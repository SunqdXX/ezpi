//go:build !linux

package engine

import "io"

func applyTTL(w io.Writer, ttl int) func() { return func() {} }
