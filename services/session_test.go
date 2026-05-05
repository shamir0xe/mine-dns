package services

import (
	"shamir0xe/mine-dns/dependencies"
	"testing"
	"time"
)

func newTestResolver() *Resolver {
	return &Resolver{
		blacklist:        []string{"instagram", "facebook"},
		directDomains:    []string{"*.ir", "local.test"},
		directDNSServers: []string{"178.22.122.100"},
		blackholeIP:      "10.10.10.10",
		whitelistSubnets: []string{"127.0.0.1/32", "192.168.1.0/24"},
		defaultTTL:       time.Hour,
		httpTimeout:      10 * time.Second,
	}
}

func newTestSession() *Session {
	return &Session{
		ID:        "test",
		logger:    dependencies.NewSessionLogger("test"),
		rs:        newTestResolver(),
		startTime: time.Now(),
	}
}

// --- checkBlacklist ---

func TestCheckBlacklist_Match(t *testing.T) {
	s := newTestSession()
	if !s.checkBlacklist("instagram.com.") {
		t.Error("expected instagram.com. to be blacklisted")
	}
}

func TestCheckBlacklist_NoMatch(t *testing.T) {
	s := newTestSession()
	if s.checkBlacklist("google.com.") {
		t.Error("expected google.com. to not be blacklisted")
	}
}

func TestCheckBlacklist_CaseInsensitive(t *testing.T) {
	s := newTestSession()
	if !s.checkBlacklist("INSTAGRAM.COM.") {
		t.Error("expected uppercase INSTAGRAM.COM. to be blacklisted")
	}
}

func TestCheckBlacklist_SubstringMatch(t *testing.T) {
	s := newTestSession()
	if !s.checkBlacklist("api.instagram.com.") {
		t.Error("expected subdomain of blacklisted domain to match")
	}
}

// --- matchDirectDomain ---

func TestMatchDirectDomain(t *testing.T) {
	s := newTestSession()
	cases := []struct {
		name string
		want bool
	}{
		{"example.ir.", true},
		{"sub.example.ir.", true},
		{"IR.", false}, // bare TLD must not match
		{"example.com.", false},
		{"notir.org.", false},
		{"local.test.", true},      // exact match
		{"sub.local.test.", false}, // exact pattern doesn't cover subdomains
	}
	for _, c := range cases {
		got := s.matchDirectDomain(c.name)
		if got != c.want {
			t.Errorf("matchDirectDomain(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMatchDirectDomain_CaseInsensitive(t *testing.T) {
	s := newTestSession()
	if !s.matchDirectDomain("EXAMPLE.IR.") {
		t.Error("expected case-insensitive match for EXAMPLE.IR.")
	}
}

// --- whitelistedAddr ---

func TestWhitelistedAddr_Allowed(t *testing.T) {
	s := newTestSession()
	if !s.whitelistedAddr("127.0.0.1:5353") {
		t.Error("expected 127.0.0.1 to be whitelisted")
	}
}

func TestWhitelistedAddr_SubnetAllowed(t *testing.T) {
	s := newTestSession()
	if !s.whitelistedAddr("192.168.1.100:5353") {
		t.Error("expected 192.168.1.100 to be whitelisted via 192.168.1.0/24")
	}
}

func TestWhitelistedAddr_Denied(t *testing.T) {
	s := newTestSession()
	if s.whitelistedAddr("10.0.0.1:5353") {
		t.Error("expected 10.0.0.1 to be denied")
	}
}

func TestWhitelistedAddr_InvalidAddr(t *testing.T) {
	s := newTestSession()
	if s.whitelistedAddr("not-an-address") {
		t.Error("expected invalid address to be denied")
	}
}

// --- subnetMatch ---

func TestSubnetMatch(t *testing.T) {
	s := newTestSession()
	cases := []struct {
		cidr string
		ip   string
		want bool
	}{
		{"192.168.1.0/24", "192.168.1.100", true},
		{"192.168.1.0/24", "192.168.2.1", false},
		{"127.0.0.1/32", "127.0.0.1", true},
		{"127.0.0.1/32", "127.0.0.2", false},
		{"invalid-cidr", "127.0.0.1", false},
		{"192.168.1.0/24", "not-an-ip", false},
	}
	for _, c := range cases {
		got := s.subnetMatch(c.cidr, c.ip)
		if got != c.want {
			t.Errorf("subnetMatch(%q, %q) = %v, want %v", c.cidr, c.ip, got, c.want)
		}
	}
}
