package trojan

import (
	"crypto/tls"
	"github.com/koomox/goproxy/tunnel"
	"net"
	"time"
)

func Dial(network, address, ServerName string, timeout time.Duration, tlsCfg *tls.Config) (conn net.Conn, err error) {
	rc, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		return nil, err
	}
	tlsCfg.ServerName = ServerName
	conn = tls.Client(rc, tlsCfg)
	err = conn.(*tls.Conn).Handshake()
	return
}

func DialConn(hash []byte, addr string, conn net.Conn) (tunnel.Conn, error) {
	address, err := tunnel.ResolveAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &OutboundConn{Conn: conn, hash: hash, metadata: &tunnel.Metadata{Command: Connect, Address: address}}, nil
}

func DialPacket(hash []byte, conn net.Conn) (tunnel.PacketConn, error) {
	return &PacketConn{&OutboundConn{Conn: conn, hash: hash, metadata: &tunnel.Metadata{Command: Associate, Address: &tunnel.Address{}}}}, nil
}
