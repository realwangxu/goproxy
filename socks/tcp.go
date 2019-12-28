package socks

import (
	"fmt"
	"net"
)

func (h *handle) listen() error {
	l, err := net.Listen("tcp", h.Addr)
	if err != nil {
		return fmt.Errorf("listen tcp err: %v", err.Error())
	}

	go h.accept(l)

	return nil
}

func (h *handle) accept(l net.Listener) {
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			h.Errorf("tcp accept %v", err.Error())
			return
		}

		go h.handler(c)
	}

	return
}

func (h *handle) handler(c net.Conn) {
	defer c.Close()
	c.(*net.TCPConn).SetKeepAlive(true)

	var (
		addrType byte
		addr     string
		host     string
		port     string
		r        Addr
		raw      []byte
		err      error
	)

	buf := make([]byte, 1)
	if _, err = c.Read(buf); err != nil {
		h.Errorf("get peer first char data failed! %v ", err.Error())
		return
	}

	first := buf[0]
	switch first {
	case Version5:
		r, err = OnceAccept(first, c)
		if err != nil {
			if err == InfoUDPAssociate {
				buf := make([]byte, 1)
				// block here
				for {
					_, err := c.Read(buf)
					if err, ok := err.(net.Error); ok && err.Timeout() {
						continue
					}
					return
				}
			}
			return
		}
		addrType, host, port = r.Parse()
		addr = net.JoinHostPort(host, port)
	case Version4:
		h.Errorf("socks4 failed!")
		return
	default:
		addrType, addr, raw, err = h.HttpAccept(first, c)
		if err == nil {
			host, port, err = net.SplitHostPort(addr)
		}
	}

	if err != nil {
		h.Errorf("Connecting ReadAddr failed %v", err.Error())
		return
	}

	rc, err := h.matchRuleAndCreateConn(addrType, addr, host, raw, c)
	if err != nil {
		h.Errorf(err.Error())
		return
	}

	defer rc.Close()

	_, _, err = relay(rc, c)
	if err != nil {
		if err, ok := err.(*net.OpError); ok && err.Timeout() {
			return // ignore i/o timeout
		}
		h.Errorf("relay error: %v", err)
	}
}

func (h *handle) matchRuleAndCreateConn(addrType byte, addr, host string, raw []byte, c net.Conn) (net.Conn, error) {
	hosts := h.MatchHosts(host)
	if hosts != "" {
		h.Infof("[%s] => [%s] => [%s]", hosts, "direct", addr)
		return net.Dial("tcp", addr)
	}

	match, action := h.MatchRule(host, addrType)
	switch match {
	case "final", "default":
	default:
		switch action {
		case "proxy":
		default:
			h.Infof("[%s] => [%s] => [%s]", match, "direct", addr)
			return net.Dial("tcp", addr)
		}
	}

	h.Infof("[%s] => [%s] => [%s]", match, "proxy", addr)
	return h.CreateRemoteConn(addr, raw, c)
}
