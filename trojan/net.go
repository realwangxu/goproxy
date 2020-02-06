package trojan

import (
	"bytes"
	"crypto/tls"
	"net"
)

type Logger interface {
	Info(...interface{})
	Infof(string, ...interface{})
	Error(...interface{})
	Errorf(string, ...interface{})
}

type Worker interface {
	Auth([]byte) bool
	Srv([]byte, net.Conn)
}

type trojan struct {
	front     string
	addr      string
	domain    string
	tlsConfig *tls.Config
	worker    Worker
	log       Logger
}

func New(front, addr, domain string, tlsConfig *tls.Config, worker Worker, log Logger) *trojan {
	return &trojan{
		front:     front,
		addr:      addr,
		domain:    domain,
		tlsConfig: tlsConfig,
		worker:    worker,
		log:       log,
	}
}

func (p *trojan) ListenAndSrv() {
	l, err := tls.Listen("tcp", p.addr, p.tlsConfig)
	if err != nil {
		p.log.Errorf("Listen %v failed %v", p.addr, err.Error())
		return
	}

	p.log.Infof("Starting Listen TCP %v %v ...", p.domain, p.addr)

	for {
		c, err := l.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			p.log.Errorf("Accept failed %v", err.Error())
			break
		}

		go p.handler(c)
	}
}

func (p *trojan) handler(c net.Conn) {
	defer c.Close()

	b := make([]byte, 1024)
	n, err := c.Read(b)
	if err != nil {
		p.log.Errorf("first read err %v", err.Error())
		return
	}

	b = b[:n]
	if n < frameOffsetType {
		p.log.Errorf("packet short %v", n)
		p.frontPage(c, b)
		return
	}
	first := bytes.Index(b[:frameOffsetType], CRLF)
	if first < 0 || first != frameOffsetPassword {
		p.log.Errorf("packet err %v", first)
		p.frontPage(c, b)
		return
	}

	password := b[:frameOffsetPassword]
	if !p.worker.Auth(password) { // user auth
		p.log.Errorf("auth failed %v", string(password))
		p.frontPage(c, b)
		return
	}

	p.worker.Srv(b[:n], c)
}

// forward http server
func (p *trojan) frontPage(c net.Conn, b []byte) {
	rc, err := net.Dial("tcp", p.front)
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
		p.log.Errorf("relay error: %v", err)
	}
}
