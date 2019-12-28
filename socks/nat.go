package socks

import (
	"net"
	"sync"
	"time"
)

type mode int

const (
	RemoteServer mode = iota
	LocalClient
	RelayClient
	SocksClient
	SocksForward
	DirectForward
)

const UdpBufSize = 64 * 1024

// Packet NAT table
type Natmap struct {
	sync.RWMutex
	m       map[string]net.PacketConn
	timeout time.Duration
}

func NewNATmap(timeout time.Duration) *Natmap {
	m := &Natmap{}
	m.m = make(map[string]net.PacketConn)
	m.timeout = timeout
	return m
}

func (m *Natmap) Get(key string) net.PacketConn {
	m.RLock()
	defer m.RUnlock()
	return m.m[key]
}

func (m *Natmap) Set(key string, pc net.PacketConn) {
	m.Lock()
	defer m.Unlock()

	m.m[key] = pc
}

func (m *Natmap) Del(key string) net.PacketConn {
	m.Lock()
	defer m.Unlock()

	pc, ok := m.m[key]
	if ok {
		delete(m.m, key)
		return pc
	}
	return nil
}

func (m *Natmap) Add(peer net.Addr, dst, src net.PacketConn, role mode) {
	m.Set(peer.String(), src)

	go func() {
		timedCopy(dst, peer, src, m.timeout, role)
		if pc := m.Del(peer.String()); pc != nil {
			pc.Close()
		}
	}()
}

// copy from src to dst at target with read timeout
func timedCopy(dst net.PacketConn, target net.Addr, src net.PacketConn, timeout time.Duration, role mode) error {
	buf := make([]byte, UdpBufSize)

	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, raddr, err := src.ReadFrom(buf)
		if err != nil {
			return err
		}

		switch role {
		case RemoteServer: // server -> client: add original packet source
			srcAddr := ParseAddr(raddr.String())
			copy(buf[len(srcAddr):], buf[:n])
			copy(buf, srcAddr)
			_, err = dst.WriteTo(buf[:len(srcAddr)+n], target)
		case LocalClient: // client -> SocksClient
			srcAddr := SplitAddr(buf[3:n])
			_, err = dst.WriteTo(buf[3+len(srcAddr):n], target)
		case RelayClient: // client -> user: strip original packet source
			srcAddr := SplitAddr(buf[:n])
			_, err = dst.WriteTo(buf[len(srcAddr):n], target)
		case SocksClient: // client -> socks5 program: just set RSV and FRAG = 0
			_, err = dst.WriteTo(append([]byte{0, 0, 0}, buf[:n]...), target)
		case DirectForward:
			_, err = dst.WriteTo(buf[:n], target)
		case SocksForward:
			_, err = dst.WriteTo(buf[:n], target)
		}

		if err != nil {
			return err
		}
	}
}
