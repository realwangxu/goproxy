package goproxy

const (
	AddrTypeIPv4       byte = 0x01
	AddrTypeDomainName byte = 0x03
	AddrTypeIPv6       byte = 0x04

	ActionAccept = "ACCEPT"
	ActionProxy  = "PROXY"
	ActionReject = "REJECT"
	ActionDirect = "DIRECT"
)

type Metadata interface {
	AddrType() byte
	Port() string
	Host() string
	String() string
}

type Rule interface {
	RuleType() byte
	Adapter() string
	String() string
}

type Match interface {
	MatchBypass(string) bool
	MatchHosts(string) string
	MatchPort(string) bool
	MatchRule(Metadata) Rule
}

type Logger interface {
	Info(...interface{})
	Infof(string, ...interface{})
	Error(...interface{})
	Errorf(string, ...interface{})
}