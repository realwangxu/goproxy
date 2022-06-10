package freedom

import (
	"fmt"
	"github.com/koomox/goproxy/tunnel"
	"net"
	"time"
)

type PacketConn struct {
	timeout time.Duration
	*net.UDPConn
}

type Conn struct {
	timeout time.Duration
	net.Conn
}

func (c *PacketConn) WriteWithMetadata(p []byte, m *tunnel.Metadata) (int, error) {
	return c.WriteTo(p, m.Address)
}

func (c *PacketConn) ReadWithMetadata(p []byte) (int, *tunnel.Metadata, error) {
	if err := c.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, nil, err
	}
	n, addr, err := c.ReadFrom(p)
	if err != nil {
		return 0, nil, err
	}
	address, err := tunnel.ResolveAddr("udp", addr.String())
	if err != nil {
		return 0, nil, err
	}
	metadata := &tunnel.Metadata{
		Address: address,
	}
	return n, metadata, nil
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if err := c.SetDeadline(time.Now().Add(c.timeout)); err != nil {
			return 0, err
		}
		return c.WriteToUDP(p, udpAddr)
	}
	ip, err := addr.(*tunnel.Address).ResolveIP()
	if err != nil {
		return 0, err
	}
	udpAddr := &net.UDPAddr{
		IP:   ip,
		Port: addr.(*tunnel.Address).Port,
	}
	if err = c.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.WriteToUDP(p, udpAddr)
}

func DialPacket(timeout time.Duration) (tunnel.PacketConn, error) {
	conn, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("freedom failed to listen udp socket %v", err.Error())
	}
	return &PacketConn{UDPConn: conn.(*net.UDPConn), timeout: timeout}, nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if err := c.Conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	if err := c.Conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func DialConn(network, address string, timeout time.Duration) (*Conn, error) {
	conn, err := net.DialTimeout(network, address, time.Second*3)
	if err != nil {
		return nil, err
	}
	return &Conn{Conn: conn, timeout: timeout}, nil
}
