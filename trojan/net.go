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

func (this *trojan) ListenAndSrv() {
	l, err := tls.Listen("tcp", this.addr, this.tlsConfig)
	if err != nil {
		this.log.Errorf("Listen %v failed %v", this.addr, err.Error())
		return
	}

	this.log.Infof("Starting Listen TCP %v %v ...", this.domain, this.addr)

	for {
		c, err := l.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			this.log.Errorf("Accept failed %v", err.Error())
			break
		}

		go this.handler(c)
	}
}

func (this *trojan) handler(c net.Conn) {
	defer c.Close()

	b := make([]byte, 1024)
	n, err := c.Read(b)
	if err != nil {
		this.log.Errorf("first read err %v", err.Error())
		return
	}

	b = b[:n]
	if n < frameOffsetType {
		this.log.Errorf("packet short %v", n)
		this.frontPage(c, b)
		return
	}
	first := bytes.Index(b[:frameOffsetType], CRLF)
	if first < 0 || first != frameOffsetPassword {
		this.log.Errorf("packet err %v", first)
		this.frontPage(c, b)
		return
	}

	password := b[:frameOffsetPassword]
	if !this.worker.Auth(password) { // user auth
		this.log.Errorf("auth failed %v", string(password))
		this.frontPage(c, b)
		return
	}

	this.worker.Srv(b[:n], c)
}

// forward http server
func (this *trojan) frontPage(c net.Conn, b []byte) {
	rc, err := net.Dial("tcp", this.front)
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
		this.log.Errorf("relay error: %v", err)
	}
}
