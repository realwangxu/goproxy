package trojan

import (
	"crypto/tls"
	"github.com/koomox/goproxy/tunnel"
	"net"
)

func Dial(network, address, ServerName string, tlsCfg *tls.Config) (conn net.Conn, err error) {
	rc, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	tlsCfg.ServerName = ServerName
	conn = tls.Client(rc, tlsCfg)
	err = conn.(*tls.Conn).Handshake()
	return
}

func DialConn(hash, addr string, conn net.Conn) (tunnel.Conn, error) {
	address, err := tunnel.ResolveAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &OutboundConn{Conn: conn, hash: hash, metadata: &tunnel.Metadata{Command: Connect, Address: address}}, nil
}

func DialPacket(hash string, conn net.Conn) (tunnel.PacketConn, error) {
	return &PacketConn{&OutboundConn{Conn: conn, hash: hash, metadata: &tunnel.Metadata{Command: Associate, Address: &tunnel.Address{}}}}, nil
}
