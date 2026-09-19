//go:build linux

package main

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type queueRules interface{ remove() }

type nftQueueRules struct {
	conn  *nftables.Conn
	table *nftables.Table
}

const queueEarlyPackets = 8

func installQueueRules(cfg *Config, queueNum uint16, onlyDstIP []byte) (queueRules, error) {
	if r, err := installQueueNft(cfg, queueNum, onlyDstIP); err == nil {
		return r, nil
	} else {
		if r2, e2 := installQueueIptables(cfg, queueNum, onlyDstIP); e2 == nil {
			return r2, nil
		} else {
			return nil, fmt.Errorf("nftables failed (%v) and iptables failed (%v)", err, e2)
		}
	}
}

func installQueueNft(cfg *Config, queueNum uint16, onlyDstIP []byte) (*nftQueueRules, error) {
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, err
	}

	conn.DelTable(&nftables.Table{Name: "ezpi_q", Family: nftables.TableFamilyIPv4})
	conn.Flush()

	tbl := conn.AddTable(&nftables.Table{
		Name:   "ezpi_q",
		Family: nftables.TableFamilyIPv4,
	})
	ch := conn.AddChain(&nftables.Chain{
		Name:     "out",
		Table:    tbl,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityMangle,
	})

	conn.AddRule(&nftables.Rule{
		Table: tbl,
		Chain: ch,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(cfg.FWMark)},
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})

	conn.AddRule(&nftables.Rule{
		Table: tbl,
		Chain: ch,
		Exprs: append(dstFilter(onlyDstIP), []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(cfg.TargetPort)},
			&expr.Ct{Key: expr.CtKeyPKTS, Register: 1},
			&expr.Cmp{Op: expr.CmpOpLt, Register: 1, Data: binaryutil.NativeEndian.PutUint64(queueEarlyPackets)},
			&expr.Queue{Num: queueNum, Flag: expr.QueueFlagBypass},
		}...),
	})

	if err := conn.Flush(); err != nil {
		conn.CloseLasting()
		return nil, fmt.Errorf("installing queue rule: %w", err)
	}
	return &nftQueueRules{conn: conn, table: tbl}, nil
}

func (q *nftQueueRules) remove() {
	if q.conn == nil {
		return
	}
	q.conn.DelTable(q.table)
	q.conn.Flush()
	q.conn.CloseLasting()
	q.conn = nil
}

func dstFilter(ip []byte) []expr.Any {
	if len(ip) != 4 {
		return nil
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip},
	}
}
