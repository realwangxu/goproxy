package trojan

import (
	"crypto/tls"
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

func DialConn(hash, addr string, conn net.Conn) (Conn, error) {
	address, err := ResolveAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &OutboundConn{Conn: conn, hash: hash, metadata: &Metadata{Command: Connect, Address: address}}, nil
}

func DialPacket(hash, addr string, conn net.Conn) (PacketConn, error) {
	address, err := ResolveAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return &UDPConn{&OutboundConn{Conn: conn, hash: hash, metadata: &Metadata{Command: Associate, Address: address}}}, nil
}
