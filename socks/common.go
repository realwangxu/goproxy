package socks

import (
	"github.com/koomox/goproxy"
)

// SOCKS request commands as defined in RFC 1928 section 4.
const (
	CmdConnect      byte = 0x01
	CmdBind         byte = 0x02
	CmdUDPAssociate byte = 0x03
)

// SOCKS address types as defined in RFC 1928 section 5.
const (
	AtypIPv4       byte = 0x01
	AtypDomainName byte = 0x03
	AtypIPv6       byte = 0x04
)

// MaxAddrLen is the maximum size of SOCKS address in bytes.
const MaxAddrLen = 1 + 1 + 255 + 2

const (
	Version5 byte = 0x05
	Version4 byte = 0x04
)

const (
	flagTCP byte = 0x1
	flagUDP byte = 0x2
)

const (
	TypeIPv4   byte = 0x01
	TypeDomain byte = 0x03
	TypeIPv6   byte = 0x04
)

type Server struct {
	Addr   string
	match  goproxy.Match
	conn   goproxy.Conn
	log    goproxy.Logger
	flag   byte
}

func New(addr string, conn goproxy.Conn, match goproxy.Match, log goproxy.Logger) *Server {
	return &Server{
		Addr:   addr,
		match:  match,
		conn:   conn,
		log:    log,
		flag:   0,
	}
}

func (r *Server) ListenAndSrv() {
	r.run()
}

func (r *Server) removeTCP() { r.flag &= flagUDP }

func (r *Server) removeUDP() { r.flag &= flagTCP }

func (r *Server) addTCP() { r.flag |= flagTCP }

func (r *Server) addUDP() { r.flag |= flagUDP }

func (r *Server) run() {
	if r.flag&flagTCP != flagTCP {
		go r.listen()
	}
	if r.flag&flagUDP != flagUDP {
		go r.listenUDP()
	}
}
