package socks

import (
	"net"
)

func (r *Server) listenUDP() {
	c, err := net.ListenPacket("udp", r.Addr)
	if err != nil {
		r.log.Errorf("UDP local listen error: %v", err)
		return
	}
	defer r.removeUDP()
	defer c.Close()

	r.addUDP()
	buf := make([]byte, UdpBufSize)

	for {
		n, raddr, err := c.ReadFrom(buf)
		if err != nil {
			if er, ok := err.(*net.OpError); ok && er.Timeout() {
				continue // ignore i/o timeout
			}
			r.log.Errorf("UDP local read error: %v", err)
			return
		}

		if n < 3 {
			continue
		}

		addr := SplitAddr(buf[3:n])
		if addr == nil {
			continue
		}
		if n <= len(addr)+3 {
			continue
		}

		r.conn.CreatePacketConn(raddr, buf[3:n], c) // 第一件事就是发出去，否则会导致数据被覆盖掉
	}
}
