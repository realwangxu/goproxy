package natmap

import (
	"github.com/koomox/goproxy/socks"
	"github.com/koomox/goproxy/trojan"
	"net"
	"sync"
	"time"
)

// Packet NAT table
type TcpNatmap struct {
	sync.RWMutex
	m       map[string]net.Conn
	timeout time.Duration
}

func NewTcpNatmap(timeout time.Duration) *TcpNatmap {
	m := &TcpNatmap{}
	m.m = make(map[string]net.Conn)
	m.timeout = timeout
	return m
}

func (m *TcpNatmap) Get(key string) net.Conn {
	m.RLock()
	defer m.RUnlock()
	return m.m[key]
}

func (m *TcpNatmap) Set(key string, pc net.Conn) {
	m.Lock()
	defer m.Unlock()

	m.m[key] = pc
}

func (m *TcpNatmap) Del(key string) net.Conn {
	m.Lock()
	defer m.Unlock()

	pc, ok := m.m[key]
	if ok {
		delete(m.m, key)
		return pc
	}
	return nil
}

func (m *TcpNatmap) Add(peer net.Addr, dst net.PacketConn, src net.Conn, role byte) {
	m.Set(peer.String(), src)

	go func() {
		m.timedCopy(dst, peer, src, m.timeout, role)
		if pc := m.Del(peer.String()); pc != nil {
			pc.Close()
		}
	}()
}

// copy from src to dst at target with read timeout
func (m *TcpNatmap) timedCopy(dst net.PacketConn, target net.Addr, src net.Conn, timeout time.Duration, role byte) error {
	var (
		buf      []byte
		buffer   []byte
		addr     []byte
		payload  []byte
		buffered []byte
		err      error
	)
	buf = make([]byte, socks.UdpBufSize)
	for {
		if buffered == nil {
			src.SetReadDeadline(time.Now().Add(timeout))
			n, err := src.Read(buf)
			if err != nil {
				return err
			}
			buffer = buf[:n]
		} else {
			buffer = buffered
			buffered = nil
		}
		addr, payload, buffered, err = trojan.ReadUDPacket(buffer, src)
		if addr == nil || payload == nil {
			return errors.New("parse failed")
		}
		if err != nil {
			return err
		}

		switch role {
		case RemoteServer: // server -> client: add original packet source
			srcAddr := socks.ParseAddr(target.String())
			copy(buf[len(srcAddr):], buf)
			copy(buf, srcAddr)
			_, err = dst.WriteTo(buf[:len(srcAddr)], target)
		case RelayClient: // client -> user: strip original packet source
			_, err = dst.WriteTo(append(addr, payload...), target)
		case SocksClient: // client -> socks5 program: just set RSV and FRAG = 0
			b := append([]byte{0, 0, 0}, addr...)
			_, err = dst.WriteTo(append(b, payload...), target)
		}

		if err != nil {
			return err
		}
	}
}
