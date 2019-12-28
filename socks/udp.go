package socks

import (
	"net"
)

func (h *handle) udpSocksLocal() {
	c, err := net.ListenPacket("udp", h.Addr)
	if err != nil {
		h.Errorf("UDP local listen error: %v", err)
		return
	}
	defer h.removeUDP()
	defer c.Close()

	h.addUDP()
	buf := make([]byte, UdpBufSize)

	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			if er, ok := err.(*net.OpError); ok && er.Timeout() {
				continue // ignore i/o timeout
			}
			h.Errorf("UDP local read error: %v", err)
			return
		}

		if n < 3 {
			continue
		}

		raddr := SplitAddr(buf[3:n])
		if raddr == nil {
			continue
		}
		if n <= len(raddr)+3 {
			continue
		}

		payload := buf[3+len(raddr) : n]
		h.CreatePacketConn(raddr, payload, c) // 第一件事就是发出去，否则会导致数据被覆盖掉
	}
}
