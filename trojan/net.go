package trojan

import (
	"bytes"
	"crypto/tls"
	"net"
)

// error log func
type logFunc func(string, ...interface{})

// auth password
type authFunc func([]byte) bool

// local net.Conn, passowrd, addr, payload []byte
type srvFunc func(net.Conn, []byte, []byte, []byte)

type handle struct {
	front     string
	addr      string
	domain    string
	tlsConfig *tls.Config
	Auth      authFunc
	Srv       srvFunc
	Errorf    logFunc
	Infof     logFunc
}

func New(front, addr, domain string, tlsConfig *tls.Config, auth authFunc, srv srvFunc, err, info logFunc) *handle {
	return &handle{
		front:     front,
		addr:      addr,
		domain:    domain,
		tlsConfig: tlsConfig,
		Auth:      auth,
		Srv:       srv,
		Errorf:    err,
		Infof:     info,
	}
}

func (h *handle) ListenAndSrv() {
	l, err := tls.Listen("tcp", h.addr, h.tlsConfig)
	if err != nil {
		h.Errorf("Listen %v failed %v", h.addr, err.Error())
		return
	}

	h.Infof("Starting Listen TCP %v %v ...", h.domain, h.addr)

	for {
		c, err := l.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			h.Errorf("Accept failed %v", err.Error())
			break
		}

		go h.handler(c)
	}
}

func (h *handle) handler(c net.Conn) {
	defer c.Close()

	b := make([]byte, 1024)
	n, err := c.Read(b)
	if err != nil {
		h.Errorf("first read err %v", err.Error())
		return
	}

	b = b[:n]
	if n < cmdPrefixLen {
		h.Errorf("packet short %v", n)
		h.frontPage(c, b)
		return
	}
	first := bytes.Index(b[:cmdPrefixLen], CRLF)
	if first < 0 || first != passwordPrefixLen {
		h.Errorf("packet err %v", first)
		h.frontPage(c, b)
		return
	}

	password := b[:passwordPrefixLen]
	if !h.Auth(password) { // user auth
		h.Errorf("auth failed %v", string(password))
		h.frontPage(c, b)
		return
	}

	after := b[cmdPrefixLen:]
	second := bytes.Index(after, CRLF)
	if second < 0 {
		h.Errorf("second read err %v", second)
		return
	}

	addr := after[:second]
	cmd := addr[0]
	switch cmd {
	case CmdConnect, CmdUDPAssociate:
	default:
		return
	}

	prefixLen := cmdPrefixLen + second + 2
	var payload []byte
	if prefixLen < n {
		payload = b[prefixLen:]
	}

	h.Srv(c, password, addr, payload)
}

// forward http server
func (h *handle) frontPage(c net.Conn, b []byte) {
	rc, err := net.Dial("tcp", h.front)
	if err != nil {
		return
	}
	defer rc.Close()

	if _, err = rc.Write(b); err != nil {
		return
	}

	_, _, err = relay(rc, c)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return // ignore i/o timeout
		}
		h.Errorf("relay error: %v", err)
	}
}
