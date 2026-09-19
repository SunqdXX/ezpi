//go:build linux

package main

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const nftTableFOwner = 0x2

const tableName = "ezpi"

const (
	icmpPortUnreach  = 3
	icmp6PortUnreach = 4
)

var neverRedirect4 = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"224.0.0.0/4",
	"240.0.0.0/4",
}

var neverRedirect6 = []string{
	"::1/128",
	"fe80::/10",
	"fc00::/7",
	"ff00::/8",
}

type NFT struct {
	conn   *nftables.Conn
	tables []*nftables.Table
}

func ifname(s string) []byte {
	b := make([]byte, 16)
	copy(b, s)
	return b
}

func verdictReturn() *expr.Verdict { return &expr.Verdict{Kind: expr.VerdictReturn} }

func skipCIDR(cidr string, v6 bool) ([]expr.Any, error) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	offset, width := uint32(16), uint32(4)
	ip := n.IP.To4()
	if v6 {
		offset, width = 24, 16
		ip = n.IP.To16()
	}
	if ip == nil {
		return nil, fmt.Errorf("%s is not the expected address family", cidr)
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: width},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: width,
			Mask: []byte(n.Mask), Xor: make([]byte, width)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip},
		verdictReturn(),
	}, nil
}

func Install(cfg *Config) (*NFT, error) {
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("opening netlink socket: %w", err)
	}

	families := []struct {
		family     nftables.TableFamily
		v6         bool
		skip       []string
		listenAddr string
	}{
		{nftables.TableFamilyIPv4, false, neverRedirect4, ""},
		{nftables.TableFamilyIPv6, true, neverRedirect6, ""},
	}

	var built []*nftables.Table
	for _, f := range families {
		conn.DelTable(&nftables.Table{Name: tableName, Family: f.family})
		conn.Flush()

		tbl := conn.AddTable(&nftables.Table{
			Name:   tableName,
			Family: f.family,
			Flags:  nftTableFOwner,
		})
		policy := nftables.ChainPolicyAccept
		ch := conn.AddChain(&nftables.Chain{
			Name:     "output",
			Table:    tbl,
			Type:     nftables.ChainTypeNAT,
			Hooknum:  nftables.ChainHookOutput,
			Priority: nftables.ChainPriorityNATDest,
			Policy:   &policy,
		})

		buildSkips := func() ([][]expr.Any, error) {
			out := [][]expr.Any{{
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(cfg.FWMark)},
				verdictReturn(),
			}}
			for _, name := range cfg.SkipInterfaces {
				out = append(out, []expr.Any{
					&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(name)},
					verdictReturn(),
				})
			}
			for _, cidr := range f.skip {
				e, err := skipCIDR(cidr, f.v6)
				if err != nil {
					return nil, fmt.Errorf("bad CIDR %q: %w", cidr, err)
				}
				out = append(out, e)
			}
			return out, nil
		}

		natSkips, err := buildSkips()
		if err != nil {
			conn.CloseLasting()
			return nil, err
		}
		add := func(e []expr.Any) { conn.AddRule(&nftables.Rule{Table: tbl, Chain: ch, Exprs: e}) }
		for _, s := range natSkips {
			add(s)
		}
		add([]expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(cfg.TargetPort)},
			&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(cfg.ListenPort)},
			&expr.Redir{RegisterProtoMin: 1},
		})

		qpolicy := nftables.ChainPolicyAccept
		qch := conn.AddChain(&nftables.Chain{
			Name:     "quic",
			Table:    tbl,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookOutput,
			Priority: nftables.ChainPriorityFilter,
			Policy:   &qpolicy,
		})
		quicSkips, err := buildSkips()
		if err != nil {
			conn.CloseLasting()
			return nil, err
		}
		qadd := func(e []expr.Any) { conn.AddRule(&nftables.Rule{Table: tbl, Chain: qch, Exprs: e}) }
		for _, s := range quicSkips {
			qadd(s)
		}
		rejectCode := uint8(icmpPortUnreach)
		if f.v6 {
			rejectCode = icmp6PortUnreach
		}
		qadd([]expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(cfg.TargetPort)},
			&expr.Reject{Type: unix.NFT_REJECT_ICMP_UNREACH, Code: rejectCode},
		})

		if err := conn.Flush(); err != nil {
			if f.v6 {
				log.Printf("IPv6 rules not installed (%v); IPv4 protection is active", err)
				conn.DelTable(tbl)
				conn.Flush()
				continue
			}
			conn.CloseLasting()
			return nil, fmt.Errorf("installing ruleset: %w", err)
		}
		built = append(built, tbl)
	}

	if len(built) == 0 {
		conn.CloseLasting()
		return nil, fmt.Errorf("no firewall rules could be installed")
	}
	return &NFT{conn: conn, tables: built}, nil
}

func (n *NFT) OwnerEnforced() bool {
	tables, err := n.conn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return false
	}
	for _, t := range tables {
		if t.Name == tableName {
			return t.Flags&nftTableFOwner != 0
		}
	}
	return false
}

func (n *NFT) Status() string {
	base := "nftables rules installed (" + n.Families() + ")"
	if n.OwnerEnforced() {
		return base + "; the kernel removes them automatically if EzPi stops"
	}
	return base + "; removed when EzPi stops"
}

func (n *NFT) Families() string {
	var out []string
	for _, t := range n.tables {
		if t.Family == nftables.TableFamilyIPv6 {
			out = append(out, "IPv6")
		} else {
			out = append(out, "IPv4")
		}
	}
	return strings.Join(out, "+")
}

func (n *NFT) Remove() error {
	for _, t := range n.tables {
		n.conn.DelTable(t)
	}
	err := n.conn.Flush()
	n.conn.CloseLasting()
	return err
}
