package socks

import "net"

const (
	flagTCP byte = 0x1
	flagUDP byte = 0x2
)

// first, net.Conn,  return addrType, addr, raw, err
type httpAcceptFunc func(byte, net.Conn) (byte, string, []byte, error)

type Match interface {
	MatchHosts(string) string
	MatchRule(string, byte) (string, string)
}

type Logger interface {
	Info(...interface{})
	Infof(string, ...interface{})
	Error(...interface{})
	Errorf(string, ...interface{})
}

// host, raw, net.Conn
type Conn interface {
	CreateRemoteConn(string, []byte, net.Conn) (net.Conn, error)
}

type PacketConn interface {
	CreatePacketConn(net.Addr, []byte, net.PacketConn)
}

type handle struct {
	Addr       string
	HttpAccept httpAcceptFunc
	match      Match
	conn       Conn       // tcp
	packet     PacketConn // udp
	log        Logger
	flag       byte
}

func New(addr string, accept httpAcceptFunc, conn Conn, packet PacketConn, match Match, log Logger) *handle {
	return &handle{
		Addr:       addr,
		HttpAccept: accept,
		match:      match,
		conn:       conn,
		packet:     packet,
		log:        log,
		flag:       0,
	}
}

func (this *handle) ListenAndSrv() {
	this.run()
}

func (this *handle) removeTCP() { this.flag &= flagUDP }

func (this *handle) removeUDP() { this.flag &= flagTCP }

func (this *handle) addTCP() { this.flag |= flagTCP }

func (this *handle) addUDP() { this.flag |= flagUDP }

func (this *handle) run() {
	if this.flag&flagTCP != flagTCP {
		go this.listen()
	}
	if this.flag&flagUDP != flagUDP {
		go this.listenUDP()
	}
}
