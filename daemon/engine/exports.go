package engine

import "net/netip"

const (
	RecHandshake  = recHandshake
	HSClientHello = hsClientHello
	RecHeaderLen  = recHeaderLen
	MaxRecord     = maxRecord
)

func SetResolver(r *Resolver) {
	if r == nil {
		proxyResolver = nil
		return
	}
	proxyResolver = r
}

func SetSwapPolicy(f func(netip.Addr) bool) { swapAddr = f }

func SNIHostnameSpan(hs []byte) (off, length int, err error) { return sniHostnameSpan(hs) }
