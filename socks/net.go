package socks

import "net"

// host, raw, net.Conn
type createRemoteConnFunc func(string, []byte, net.Conn) (net.Conn, error)
type createPacketConnFunc func([]byte, []byte, net.PacketConn)
type matchHostsFunc func(string) string
type matchRuleFunc func(string, byte) (string, string)
type logFunc func(string, ...interface{})

type handle struct {
	Addr             string
	MatchHosts       matchHostsFunc
	MatchRule        matchRuleFunc
	CreateRemoteConn createRemoteConnFunc // tcp
	CreatePacketConn createPacketConnFunc // udp
	Errorf           logFunc
	Infof            logFunc
}

func New(addr string, matchHosts matchHostsFunc, matchRule matchRuleFunc, c createRemoteConnFunc, u createPacketConnFunc, err, info logFunc) *handle {
	return &handle{
		Addr:             addr,
		MatchHosts:       matchHosts,
		MatchRule:        matchRule,
		CreateRemoteConn: c,
		CreatePacketConn: u,
		Errorf:           err,
		Infof:            info,
	}
}

func (h *handle) ListenAndSrv() (err error) {
	return h.listen()
}
