package services

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"shamir0xe/mine-dns/dependencies"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"golang.org/x/net/proxy"
)

type ResolverInterface interface {
	HandleDNS(w dns.ResponseWriter, r *dns.Msg)
}

type Resolver struct {
	blacklist        []string
	directDomains    []string
	directDNSServers []string
	dohURL           string
	socksServer      string
	defaultTTL       time.Duration
	httpTimeout      time.Duration
	blackholeIP      string
	cache            *dependencies.CacheStruct[dns.Msg]
}

func NewResolver(cfg *viper.Viper, cache *dependencies.CacheStruct[dns.Msg]) *Resolver {
	return &Resolver{
		blacklist:        cfg.GetStringSlice("blacklist"),
		directDomains:    cfg.GetStringSlice("direct-domains"),
		directDNSServers: cfg.GetStringSlice("direct-dns-servers"),
		dohURL:           cfg.GetString("doh-resolver"),
		socksServer:      cfg.GetString("socks-server"),
		defaultTTL:       cfg.GetDuration("cache.default-ttl"),
		httpTimeout:      cfg.GetDuration("http.timeout"),
		blackholeIP:      cfg.GetString("blackhole-ip"),
		cache:            cache,
	}
}

func (rs *Resolver) checkBlacklist(name string) bool {
	name = strings.ToLower(name)
	for _, blocked := range rs.blacklist {
		if strings.Contains(name, blocked) {
			return true
		}
	}
	return false
}

// matchDirectDomain checks whether name matches any direct-domains pattern.
// Patterns may use a leading wildcard (e.g. "*.ir" matches any subdomain of .ir).
func (rs *Resolver) matchDirectDomain(name string) bool {
	name = strings.ToLower(name)
	for _, pattern := range rs.directDomains {
		pattern = strings.ToLower(pattern)
		if strings.HasPrefix(pattern, "*.") {
			// "*.ir" → suffix ".ir." (DNS names carry a trailing dot)
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

func (rs *Resolver) HandleDNS(w dns.ResponseWriter, r *dns.Msg) {
	logger := dependencies.NewSessionLogger()

	q := r.Question[0]
	logger.Printf("Received query: %s %s from %s", q.Name, dns.TypeToString[q.Qtype], w.RemoteAddr())

	if rs.checkBlacklist(q.Name) {
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

	if rs.matchDirectDomain(q.Name) {
		logger.Printf("Resolving %s directly via direct-dns-servers", q.Name)
		resp, err = rs.resolveDirect(r, logger)
	} else {
		resp, err = rs.resolveDoH(r)
	}

	if err != nil {
		logger.Printf("Resolve error for %s: %v", cacheKey, err)
		return
	}

	rs.cache.Set(cacheKey, resp, rs.defaultTTL, logger)

	w.WriteMsg(resp)
}

func (rs *Resolver) resolveDirect(query *dns.Msg, logger *dependencies.SessionLogger) (*dns.Msg, error) {
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

func (rs *Resolver) resolveDoH(query *dns.Msg) (*dns.Msg, error) {
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
