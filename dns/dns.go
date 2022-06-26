package dns

import (
	"errors"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Server struct {
	sync.RWMutex
	servers    []string
	timeout    time.Duration
	cache      map[string]*Resolver
	RetryTimes int
	r          *rand.Rand
}

type Resolver struct {
	ips  []net.IP
	last time.Time
}

var current = &Server{}

func Background() *Server {
	return current
}

func New(servers []string, timeout time.Duration) *Server {
	for i := range servers {
		servers[i] = net.JoinHostPort(servers[i], "53")
	}
	return &Server{servers: servers, timeout: timeout, cache: make(map[string]*Resolver), RetryTimes: len(servers) * 2, r: rand.New(rand.NewSource(time.Now().UnixNano()))}
}

func WithBackground(server *Server, timeout time.Duration) {
	current = server
	current.dispatchLoop(timeout)
}

func (r *Server) LookupHost(host string) (result []net.IP, err error) {
	if result = r.Get(host); result != nil {
		return
	}
	if result, err = r.lookupHost(host, r.RetryTimes); err != nil {
		return
	}
	r.Set(host, result)
	return
}

func (r *Server) lookupHost(host string, triesLeft int) ([]net.IP, error) {
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{dns.Fqdn(host), dns.TypeA, dns.ClassINET}
	in, err := dns.Exchange(m1, r.servers[r.r.Intn(len(r.servers))])

	result := []net.IP{}

	if err != nil {
		if strings.HasSuffix(err.Error(), "i/o timeout") && triesLeft > 0 {
			triesLeft--
			return r.lookupHost(host, triesLeft)
		}
		return result, err
	}

	if in != nil && in.Rcode != dns.RcodeSuccess {
		return result, errors.New(dns.RcodeToString[in.Rcode])
	}

	for _, record := range in.Answer {
		if t, ok := record.(*dns.A); ok {
			result = append(result, t.A)
		}
	}
	return result, err
}

func (r *Server) Get(host string) []net.IP {
	r.RLock()
	defer r.RUnlock()

	if d, ok := r.cache[host]; ok {
		if time.Now().Sub(d.last) < r.timeout {
			return d.ips
		}
	}

	return nil
}

func (r *Server) Set(host string, ips []net.IP) {
	if ips == nil || len(ips) == 0 {
		return
	}

	r.Lock()
	r.cache[host] = &Resolver{ips: ips, last: time.Now()}
	r.Unlock()
}

func (r *Server) Remove(host string) {
	r.Lock()
	defer r.Unlock()

	if _, ok := r.cache[host]; ok {
		delete(r.cache, host)
	}
}

func (r *Server) cleaner() {
	if r != nil {
		r.Lock()
		r.cache = make(map[string]*Resolver, 1024)
		r.Unlock()
	}
}

func (r *Server) dispatchLoop(timeout time.Duration) {
	r.cleaner()
	time.AfterFunc(timeout, func() { r.dispatchLoop(timeout) })
}