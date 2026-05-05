package services

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"shamir0xe/mine-dns/dependencies"
	utils "shamir0xe/mine-dns/pkgs"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

type Session struct {
	ID        string
	logger    *dependencies.SessionLogger
	rs        *Resolver
	startTime time.Time
}

func NewSession(rs *Resolver) *Session {
	session := &Session{
		ID:        utils.GenerateID(),
		rs:        rs,
		startTime: time.Now(),
	}
	session.logger = dependencies.NewSessionLogger(session.ID)
	session.logger.Printf("Session started")
	return session
}

func (s *Session) resolveQuery(w dns.ResponseWriter, r *dns.Msg) {
	rs := s.rs
	q := r.Question[0]
	logger := s.logger
	logger.Printf("Received query: %s %s from %s", q.Name, dns.TypeToString[q.Qtype], w.RemoteAddr())

	if s.checkBlacklist(q.Name) || !s.whitelistedAddr(w.RemoteAddr().String()) {
		logger.Printf("Redirecting %s → %s", q.Name, rs.blackholeIP)
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true

		switch q.Qtype {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    uint32(rs.defaultTTL.Seconds()),
				},
				A: net.ParseIP(rs.blackholeIP).To4(),
			})
		case dns.TypeAAAA:
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    uint32(rs.defaultTTL.Seconds()),
				},
				AAAA: net.ParseIP("::ffff:10.10.10.10"),
			})
		default:
			logger.Printf("Non-A query for blacklisted domain %s, returning empty answer", q.Name)
		}

		w.WriteMsg(resp)
		return
	}

	cacheKey := q.Name + ":" + dns.TypeToString[q.Qtype]
	msg, found := rs.cache.Get(cacheKey, logger)

	if found {
		msgPrim := msg.Copy()
		msgPrim.Id = r.Id
		w.WriteMsg(msgPrim)
		return
	}

	var (
		resp *dns.Msg
		err  error
	)

	if s.matchDirectDomain(q.Name) {
		logger.Printf("Resolving %s directly via direct-dns-servers", q.Name)
		resp, err = s.resolveDirect(r, logger)
	} else {
		resp, err = s.resolveDoH(r)
	}

	if err != nil {
		logger.Printf("Resolve error for %s: %v", cacheKey, err)
		return
	}

	rs.cache.Set(cacheKey, resp, rs.defaultTTL, logger)

	w.WriteMsg(resp)
}

func (s *Session) checkBlacklist(name string) bool {
	rs := s.rs
	name = strings.ToLower(name)
	for _, blocked := range rs.blacklist {
		if strings.Contains(name, blocked) {
			s.logger.Printf("Domain %s is blacklisted due to pattern: %s", name, blocked)
			return true
		}
	}
	return false
}

// matchDirectDomain checks whether name matches any direct-domains pattern.
// Patterns may use a leading wildcard (e.g. "*.ir" matches any subdomain of .ir).
func (s *Session) matchDirectDomain(name string) bool {
	rs := s.rs
	name = strings.ToLower(name)
	for _, pattern := range rs.directDomains {
		pattern = strings.ToLower(pattern)
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] + "."
			if strings.HasSuffix(name, suffix) {
				return true
			}
		} else {
			if name == pattern || name == pattern+"." {
				return true
			}
		}
	}
	return false
}

func (s *Session) resolveDirect(query *dns.Msg, logger *dependencies.SessionLogger) (*dns.Msg, error) {
	rs := s.rs
	client := &dns.Client{Timeout: rs.httpTimeout}
	for _, server := range rs.directDNSServers {
		addr := server
		if !strings.Contains(addr, ":") {
			addr += ":53"
		}
		resp, _, err := client.Exchange(query, addr)
		if err != nil {
			logger.Printf("Direct DNS server %s failed: %v", server, err)
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("all direct DNS servers failed for %s", query.Question[0].Name)
}

func (s *Session) resolveDoH(query *dns.Msg) (*dns.Msg, error) {
	rs := s.rs
	raw, _ := query.Pack()
	encoded := base64.RawURLEncoding.EncodeToString(raw)

	req, _ := http.NewRequest("GET", rs.dohURL+"?dns="+encoded, nil)
	req.Header.Set("Accept", "application/dns-message")

	// SOCKS5 Dialer
	dialer, err := proxy.SOCKS5("tcp", rs.socksServer, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{}
	transport.Dial = dialer.Dial

	client := &http.Client{
		Transport: transport,
		Timeout:   rs.httpTimeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	dnsResp := new(dns.Msg)
	dnsResp.Unpack(body)

	return dnsResp, nil
}

func (s *Session) whitelistedAddr(addr string) bool {
	rs := s.rs
	host, _, err := net.SplitHostPort(addr)
	res := false
	if err != nil {
		return res
	}

	for _, addr := range rs.whitelistSubnets {
		if s.subnetMatch(addr, host) {
			return true
		}
	}

	return false
}

func (s *Session) subnetMatch(cidr string, ipStr string) bool {
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	return subnet.Contains(ip)
}

func (s *Session) logSummary() {
	s.logger.Printf("Session %s completed in %fs", s.ID, time.Since(s.startTime).Seconds())
}
