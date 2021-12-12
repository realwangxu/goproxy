package socks

import (
	"net"
)

func (this *handle) listen() {
	l, err := net.Listen("tcp", this.Addr)
	if err != nil {
		this.log.Errorf("listen tcp err: %v", err.Error())
		return
	}

	this.addTCP()
	this.accept(l)
}

func (this *handle) accept(l net.Listener) {
	defer this.removeTCP()
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			this.log.Errorf("tcp accept %v", err.Error())
			return
		}

		go this.handler(c)
	}
}

func (this *handle) handler(c net.Conn) {
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
		this.log.Errorf("get peer first char data failed! %v ", err.Error())
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
		this.log.Errorf("socks4 failed!")
		return
	default:
		addrType, addr, raw, err = this.HttpAccept(first, c)
		if err == nil {
			host, port, err = net.SplitHostPort(addr)
		}
	}

	if err != nil {
		this.log.Errorf("Connecting ReadAddr failed %v", err.Error())
		return
	}

	rc, err := this.matchRuleAndCreateConn(addrType, addr, host, raw, c)
	if err != nil {
		this.log.Errorf(err.Error())
		return
	}

	defer rc.Close()

	_, _, err = relay(rc, c)
	if err != nil {
		if err, ok := err.(*net.OpError); ok && err.Timeout() {
			return // ignore i/o timeout
		}
		this.log.Errorf("relay error: %v", err)
	}
}

func (this *handle) matchRuleAndCreateConn(addrType byte, addr, host string, raw []byte, c net.Conn) (net.Conn, error) {
	hosts := this.match.MatchHosts(host)
	if hosts != "" {
		this.log.Infof(" DIRECT\t%s", addr)
		return net.Dial("tcp", addr)
	}

	_, action := this.match.MatchRule(host, addrType)
	this.log.Infof(" %s\t%s", action, addr)
	switch action {
	case "PROXY":
		return this.conn.CreateRemoteConn(addr, raw, c)
	case "CN", "DIRECT":
		return net.Dial("tcp", addr)
	default:
		return this.conn.CreateRemoteConn(addr, raw, c)
	}
}