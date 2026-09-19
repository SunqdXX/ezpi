package engine

const (
	RecHandshake  = recHandshake
	HSClientHello = hsClientHello
	RecHeaderLen  = recHeaderLen
	MaxRecord     = maxRecord
)

func SetResolver(r *Resolver) { proxyResolver = r }

func SNIHostnameSpan(hs []byte) (off, length int, err error) { return sniHostnameSpan(hs) }
