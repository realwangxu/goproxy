package natmap

import (
	"github.com/koomox/goproxy/socks"
	"github.com/koomox/goproxy/trojan"
	"net"
	"sync"
	"time"
)

// Packet NAT table
type UdpNatmap struct {
	sync.RWMutex
	m       map[string]net.PacketConn
	timeout time.Duration
}

func NewUdpNatmap(timeout time.Duration) *UdpNatmap {
	m := &UdpNatmap{}
	m.m = make(map[string]net.PacketConn)
	m.timeout = timeout
	return m
}

func (m *UdpNatmap) Get(key string) net.PacketConn {
	m.RLock()
	defer m.RUnlock()
	return m.m[key]
}

func (m *UdpNatmap) Set(key string, pc net.PacketConn) {
	m.Lock()
	defer m.Unlock()

	m.m[key] = pc
}

func (m *UdpNatmap) Del(key string) net.PacketConn {
	m.Lock()
	defer m.Unlock()

	pc, ok := m.m[key]
	if ok {
		delete(m.m, key)
		return pc
	}
	return nil
}

func (m *UdpNatmap) Add(peer net.Addr, dst net.Conn, src net.PacketConn, role mode) {
	m.Set(peer.String(), src)

	go func() {
		m.timedCopy(dst, peer, src, m.timeout, byte)
		if pc := m.Del(peer.String()); pc != nil {
			pc.Close()
		}
	}()
}

// copy from src to dst at target with read timeout
func (m *UdpNatmap) timedCopy(dst net.Conn, target net.Addr, src net.PacketConn, timeout time.Duration, role byte) error {
	buf := make([]byte, udpBufSize)

	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, raddr, err := src.ReadFrom(buf)
		if err != nil {
			return err
		}

		switch role {
		case RemoteServer: // server -> client: add original packet source
			srcAddr := socks.ParseAddr(raddr.String())
			_, err = dst.Write(trojan.MakeUDPacket(srcAddr, buf[:n]))
		case RelayClient: // client -> user: strip original packet source
			srcAddr := socks.SplitAddr(buf[:n])
			_, err = dst.Write(trojan.MakeUDPacket(srcAddr, buf[:n]))
		case SocksClient: // client -> socks5 program: just set RSV and FRAG = 0
			_, err = dst.Write(buf[:n])
		}

		if err != nil {
			return err
		}
	}
}
