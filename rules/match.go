package rules

import (
	"net"
	"regexp"
	"strings"
	"github.com/koomox/goproxy"
)

func (c *Filter) MatchBypass(addr string) bool {
	if c.bypassDomains != nil {
		ip := net.ParseIP(addr)
		for _, h := range c.bypassDomains {
			var bypass = false
			var isIp = nil != ip
			switch h.(type) {
			case net.IP:
				if isIp {
					bypass = ip.Equal(h.(net.IP))
				}
			case *net.IPNet:
				if isIp {
					bypass = h.(*net.IPNet).Contains(ip)
				}
			case string:
				dm := h.(string)
				r := regexp.MustCompile("^" + dm + "$")
				bypass = r.MatchString(addr)
			}
			if bypass {
				return true
			}
		}
	}

	return false
}

func (c *Filter) MatchHosts(host string) string {
	for _, rule := range c.ruleHosts {
		if strings.EqualFold(host, rule.Host) {
			return rule.Addr
		}
	}

	return ""
}

func (c *Filter) MatchPort(port string) bool {
	if _, ok := c.rulePort.Get(port); ok {
		return true
	}

	return false
}

func (c *Filter) MatchRule(m goproxy.Metadata) goproxy.Rule {
	host := m.Host()
	switch m.AddrType() {
	case AddrTypeDomainName:
		if r := c.matchDomain(host); r != nil {
			return r
		}
	case AddrTypeIPv4, AddrTypeIPv6:
		if r := c.matchIpRule(host); r != nil {
			return r
		}
	}
	if c.ruleFinal != nil {
		return c.ruleFinal
	}
	return &IRule{ruleType: 0, word: "match", adapter: ActionDirect}
}
