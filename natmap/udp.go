package natmap

import (
	"github.com/koomox/goproxy/socks"
	"github.com/koomox/goproxy/trojan"
	"net"
	"sync"
	"time"
)

// Packet NAT table
type UDPnatmap struct {
	sync.RWMutex
	m       map[string]net.PacketConn
	timeout time.Duration
}

func NewUDPnatmap(timeout time.Duration) *UDPnatmap {
	m := &UDPnatmap{}
	m.m = make(map[string]net.PacketConn)
	m.timeout = timeout
	return m
}

func (m *UDPnatmap) Get(key string) net.PacketConn {
	m.RLock()
	defer m.RUnlock()
	return m.m[key]
}

func (m *UDPnatmap) Set(key string, pc net.PacketConn) {
	m.Lock()
	defer m.Unlock()

	m.m[key] = pc
}

func (m *UDPnatmap) Del(key string) net.PacketConn {
	m.Lock()
	defer m.Unlock()

	pc, ok := m.m[key]
	if ok {
		delete(m.m, key)
		return pc
	}
	return nil
}

func (m *UDPnatmap) Add(peer net.Addr, dst net.Conn, src net.PacketConn, role mode) {
	m.Set(peer.String(), src)

	go func() {
		m.timedCopy(dst, peer, src, m.timeout, role)
		if pc := m.Del(peer.String()); pc != nil {
			pc.Close()
		}
	}()
}

// copy from src to dst at target with read timeout
func (m *UDPnatmap) timedCopy(dst net.Conn, target net.Addr, src net.PacketConn, timeout time.Duration, role mode) error {
	buf := make([]byte, udpBufSize)

	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, _, err := src.ReadFrom(buf)
		if err != nil {
			return err
		}

		switch role {
		case remoteServer: // server -> client: add original packet source
			srcAddr := socks.ParseAddr(target.String())
			_, err = dst.Write(trojan.EncodeUdpPacket(srcAddr, buf[:n]))
		case relayClient: // client -> user: strip original packet source
			srcAddr := socks.SplitAddr(buf[:n])
			_, err = dst.Write(trojan.EncodeUdpPacket(srcAddr, buf[:n]))
		case socksClient: // client -> socks5 program: just set RSV and FRAG = 0
			_, err = dst.Write(buf[:n])
		}

		if err != nil {
			return err
		}
	}
}
