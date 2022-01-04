package socks

import (
	"net"
	"regexp"
	"github.com/koomox/goproxy/common"
)

var (
	ip4ExpCompile        = regexp.MustCompile(`^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$`)
	domainExpCompile     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}(\.[a-zA-Z0-9][a-zA-Z0-9_-]{0,62})*(\.[a-zA-Z][a-zA-Z0-9]{0,10}){1}$`)
	ip4ExpMustCompile    = regexp.MustCompile(`((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)`)
	domainExpMustCompile = regexp.MustCompile(`[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}(\.[a-zA-Z0-9][a-zA-Z0-9_-]{0,62})*(\.[a-zA-Z][a-zA-Z0-9]{0,10}){1}`)
)

func (r *Server) listen() {
	l, err := net.Listen("tcp", r.Addr)
	if err != nil {
		r.log.Errorf("listen tcp err: %v", err.Error())
		return
	}

	r.addTCP()
	r.accept(l)
}

func (r *Server) accept(l net.Listener) {
	defer r.removeTCP()
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			r.log.Errorf("tcp accept %v", err.Error())
			return
		}

		go r.handler(c)
	}
}

func (r *Server) handler(c net.Conn) {
	defer c.Close()
	c.(*net.TCPConn).SetKeepAlive(true)

	var (
		addr *Address
		err  error
		raw  []byte
	)

	buf := make([]byte, 1)
	if _, err = c.Read(buf); err != nil {
		r.log.Errorf("get peer first char data failed! %v ", err.Error())
		return
	}

	first := buf[0]
	switch first {
	case Version5:
		if addr, err = OnceAccept(first, c); err != nil {
			if err == InfoUDPAssociate {
				buf := make([]byte, 1)
				// block here
				for {
					_, err = c.Read(buf)
					if err, ok := err.(net.Error); ok && err.Timeout() {
						continue
					}
					return
				}
			}
			return
		}
	case Version4:
		r.log.Errorf("socks4 failed!")
		return
	default:
		if addr, raw, err = HttpOnceAccept(first, c); err != nil {
			return
		}
	}

	if err != nil {
		r.log.Errorf("Connecting ReadAddr failed %v", err.Error())
		return
	}

	rc, err := r.matchRuleAndCreateConn(addr, raw, c)
	if err != nil {
		r.log.Errorf(err.Error())
		return
	}

	defer rc.Close()

	_, _, err = relay(rc, c)
	if err != nil {
		if err, ok := err.(*net.OpError); ok && err.Timeout() {
			return // ignore i/o timeout
		}
		r.log.Errorf("relay error: %v", err)
	}
}

func (r *Server) matchRuleAndCreateConn(m common.Metadata, raw []byte, c net.Conn) (net.Conn, error) {
	host := m.Host()
	if r.match.MatchBypass(host) {
		r.log.Infof(" DIRECT\t%s", m.String())
		return net.Dial("tcp", m.String())
	}

	hosts := r.match.MatchHosts(host)
	if hosts != "" {
		r.log.Infof(" DIRECT\t%s", m.String())
		return net.Dial("tcp", m.String())
	}

	if !r.match.MatchPort(m.Port()) {
		r.log.Infof(" DIRECT\t%s", m.String())
		return net.Dial("tcp", m.String())
	}

	rule := r.match.MatchRule(m)
	r.log.Infof(" %s\t%s", rule.String(), rule.Adapter())
	switch rule.Adapter() {
	case "PROXY":
		return r.conn.CreateRemoteConn(m.String(), raw, c)
	case "DIRECT":
		return net.Dial("tcp", m.String())
	default:
		return r.conn.CreateRemoteConn(m.String(), raw, c)
	}
}
