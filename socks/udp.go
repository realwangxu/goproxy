package socks

import (
	"net"
)

func (h *handle) udpSocksLocal(addr, server string) {
	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		h.Errorf("UDP local listen error: %v", err)
		return
	}
	defer c.Close()

	buf := make([]byte, UdpBufSize)

	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			h.Errorf("UDP local read error: %v", err)
			continue
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
