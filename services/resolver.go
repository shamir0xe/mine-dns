package services

import (
	"encoding/base64"
	"io"
	"log"
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
	blacklist   []string
	dohURL      string
	socksServer string
	defaultTTL  time.Duration
	httpTimeout time.Duration
	blackholeIP string
	cache       *dependencies.CacheStruct[dns.Msg]
}

func NewResolver(cfg *viper.Viper, cache *dependencies.CacheStruct[dns.Msg]) *Resolver {
	return &Resolver{
		blacklist:   cfg.GetStringSlice("blacklist"),
		dohURL:      cfg.GetString("doh-resolver"),
		socksServer: cfg.GetString("socks-server"),
		defaultTTL:  cfg.GetDuration("cache.default-ttl"),
		httpTimeout: cfg.GetDuration("http.timeout"),
		blackholeIP: cfg.GetString("blackhole-ip"),
		cache:       cache,
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

func (rs *Resolver) HandleDNS(w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	log.Printf("Received query: %s %s from %s", q.Name, dns.TypeToString[q.Qtype], w.RemoteAddr())

	if rs.checkBlacklist(q.Name) {
		log.Printf("Redirecting %s → %s", q.Name, rs.blackholeIP)
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
					Ttl:    uint32(rs.defaultTTL),
				},
				A: net.ParseIP(rs.blackholeIP).To4(),
			})
		case dns.TypeAAAA:
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    uint32(rs.defaultTTL),
				},
				AAAA: net.ParseIP("::ffff:10.10.10.10"),
			})
		default:
			log.Printf("Non-A query for blacklisted domain %s, returning empty answer", q.Name)
		}

		w.WriteMsg(resp)
		return
	}

	cacheKey := q.Name + ":" + dns.TypeToString[q.Qtype]
	msg, found := rs.cache.Get(cacheKey)

	if found {
		msgPrim := msg.Copy()
		msgPrim.Id = r.Id
		w.WriteMsg(msgPrim)
		return
	}

	// Cache miss → resolve via DoH
	resp, err := rs.resolveDoH(r)
	if err != nil {
		log.Printf("DoH resolve error for %s: %v", cacheKey, err)
		return
	}

	var ttl time.Duration
	if len(resp.Answer) > 0 {
		ttl = time.Duration(resp.Answer[0].Header().Ttl) * time.Second
	} else if resp.Rcode == dns.RcodeNameError {
		ttl = rs.defaultTTL
	} else {
		ttl = rs.defaultTTL
	}

	rs.cache.Set(cacheKey, resp, ttl)

	w.WriteMsg(resp)
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
