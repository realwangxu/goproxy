package common

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