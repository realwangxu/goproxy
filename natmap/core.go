package natmap

import "net"

type TCPNatmapInterface interface {
	Get(string) net.Conn
	Set(string, net.Conn)
	Del(string) net.Conn
	Add(net.Addr, net.PacketConn, net.Conn, byte)
}

type UDPNatmapInterface interface {
	Get(string) net.PacketConn
	Set(string, net.PacketConn)
	Del(string) net.PacketConn
	Add(net.Addr, net.Conn, net.PacketConn, byte)
}

type NatmapInterface interface {
	Get(string) net.PacketConn
	Set(string, net.PacketConn)
	Del(string) net.PacketConn
	Add(net.Addr, net.PacketConn, net.PacketConn, byte)
}