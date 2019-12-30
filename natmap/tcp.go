package natmap

import (
	"github.com/koomox/goproxy/socks"
	"github.com/koomox/goproxy/trojan"
	"net"
	"sync"
	"time"
)

// Packet NAT table
type TCPnatmap struct {
	sync.RWMutex
	m       map[string]net.Conn
	timeout time.Duration
}

func newNATmap(timeout time.Duration) *TCPnatmap {
	m := &TCPnatmap{}
	m.m = make(map[string]net.Conn)
	m.timeout = timeout
	return m
}

func (m *TCPnatmap) Get(key string) net.Conn {
	m.RLock()
	defer m.RUnlock()
	return m.m[key]
}

func (m *TCPnatmap) Set(key string, pc net.Conn) {
	m.Lock()
	defer m.Unlock()

	m.m[key] = pc
}

func (m *TCPnatmap) Del(key string) net.Conn {
	m.Lock()
	defer m.Unlock()

	pc, ok := m.m[key]
	if ok {
		delete(m.m, key)
		return pc
	}
	return nil
}

func (m *TCPnatmap) Add(peer net.Addr, dst net.PacketConn, src net.Conn, role mode) {
	m.Set(peer.String(), src)

	go func() {
		m.timedCopy(dst, peer, src, m.timeout, role)
		if pc := m.Del(peer.String()); pc != nil {
			pc.Close()
		}
	}()
}

// copy from src to dst at target with read timeout
func (m *TCPnatmap) timedCopy(dst net.PacketConn, target net.Addr, src net.Conn, timeout time.Duration, role mode) error {
	buf := make([]byte, socks.UdpBufSize)

	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, err := src.Read(buf)
		if err != nil {
			return err
		}
		addr, payload := trojan.ParsePacket(buf[:n])
		if addr == nil || payload == nil {
			return nil
		}

		switch role {
		case remoteServer: // server -> client: add original packet source
			srcAddr := socks.ParseAddr(target.String())
			copy(buf[len(srcAddr):], buf[:n])
			copy(buf, srcAddr)
			_, err = dst.WriteTo(buf[:len(srcAddr)+n], target)
		case relayClient: // client -> user: strip original packet source
			_, err = dst.WriteTo(append(addr, payload...), target)
		case socksClient: // client -> socks5 program: just set RSV and FRAG = 0
			b := append([]byte{0, 0, 0}, addr...)
			_, err = dst.WriteTo(append(b, payload...), target)
		}

		if err != nil {
			return err
		}
	}
}
