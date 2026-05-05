package services

import (
	"log"
	"shamir0xe/mine-dns/dependencies"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
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
	whitelistSubnets []string
	cache            *dependencies.CacheStruct[dns.Msg]
	sessionManager   *SessionManager
}

func NewResolver(cfg *viper.Viper, cache *dependencies.CacheStruct[dns.Msg]) *Resolver {
	rs := &Resolver{
		blacklist:        cfg.GetStringSlice("blacklist"),
		directDomains:    cfg.GetStringSlice("direct-domains"),
		directDNSServers: cfg.GetStringSlice("direct-dns-servers"),
		dohURL:           cfg.GetString("doh-resolver"),
		socksServer:      cfg.GetString("socks-server"),
		defaultTTL:       cfg.GetDuration("cache.default-ttl"),
		httpTimeout:      cfg.GetDuration("http.timeout"),
		blackholeIP:      cfg.GetString("blackhole-ip"),
		whitelistSubnets: cfg.GetStringSlice("whitelist-subnets"),
		cache:            cache,
	}
	if len(rs.whitelistSubnets) == 0 {
		log.Fatal("whitelist-subnets must not be empty — refusing to start without an IP whitelist")
	}

	rs.sessionManager = NewSessionManager(rs)

	return rs
}

func (rs *Resolver) HandleDNS(w dns.ResponseWriter, r *dns.Msg) {
	session := rs.sessionManager.NewSession()
	session.resolveQuery(w, r)
	session.logSummary()
	rs.sessionManager.EndSession(session)
}
