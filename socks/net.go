package socks

import "net"

const (
	flagTCP byte = 0x1
	flagUDP byte = 0x2
)

// first, net.Conn,  return addrType, addr, raw, err
type httpAcceptFunc func(byte, net.Conn) (byte, string, []byte, error)

// host, raw, net.Conn
type createRemoteConnFunc func(string, []byte, net.Conn) (net.Conn, error)
type createPacketConnFunc func([]byte, []byte, net.PacketConn)
type matchHostsFunc func(string) string
type matchRuleFunc func(string, byte) (string, string)
type logFunc func(string, ...interface{})

type handle struct {
	Addr             string
	HttpAccept       httpAcceptFunc
	MatchHosts       matchHostsFunc
	MatchRule        matchRuleFunc
	CreateRemoteConn createRemoteConnFunc // tcp
	CreatePacketConn createPacketConnFunc // udp
	Errorf           logFunc
	Infof            logFunc
	flag             byte
}

func New(addr string, accept httpAcceptFunc, matchHosts matchHostsFunc, matchRule matchRuleFunc, c createRemoteConnFunc, u createPacketConnFunc, err, info logFunc) *handle {
	return &handle{
		Addr:             addr,
		HttpAccept:       accept,
		MatchHosts:       matchHosts,
		MatchRule:        matchRule,
		CreateRemoteConn: c,
		CreatePacketConn: u,
		Errorf:           err,
		Infof:            info,
		flag:             0,
	}
}

func (h *handle) ListenAndSrv() {
	h.run()
	h.runUDP()
}

func (h *handle) removeTCP() { h.flag &= flagUDP }

func (h *handle) removeUDP() { h.flag &= flagTCP }

func (h *handle) addTCP() { h.flag |= flagTCP }

func (h *handle) addUDP() { h.flag |= flagUDP }

func (h *handle) run() {
	if h.flag&flagTCP != flagTCP {
		h.listen()
	}
}

func (h *handle) runUDP() {
	if h.flag&flagUDP != flagUDP {
		h.udpSocksLocal()
	}
}
