package main

import (
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

var cache = struct {
	sync.RWMutex
	data map[string]cacheEntry
}{
	data: make(map[string]cacheEntry),
}

type cacheEntry struct {
	msg      *dns.Msg
	expireAt time.Time
}

const (
	dohURL      = "https://cloudflare-dns.com/dns-query"
	socksServer = "127.0.0.1:10808"
)

func main() {
	dns.HandleFunc(".", handleDNS)

	server := &dns.Server{
		Addr: ":53",
		Net:  "udp",
	}

	log.Println("DNS server started on :53")
	log.Fatal(server.ListenAndServe())
}

func handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	log.Printf("Received query: %s %s from %s", q.Name, dns.TypeToString[q.Qtype], w.RemoteAddr())

	cacheKey := q.Name + ":" + dns.TypeToString[q.Qtype]

	// Check cache
	cache.RLock()
	entry, found := cache.data[cacheKey]
	cache.RUnlock()

	if found && time.Now().Before(entry.expireAt) {
		log.Printf("Cache HIT for %s", cacheKey)
		entryPrim := entry.msg.Copy()
		entryPrim.Id = r.Id
		w.WriteMsg(entryPrim)
		return
	}
	log.Printf("Cache MISS for %s, querying DoH upstream", cacheKey)

	// Cache miss → resolve via DoH
	resp, err := resolveDoH(r)
	if err != nil {
		log.Printf("DoH resolve error for %s: %v", cacheKey, err)
		return
	}

	var ttl time.Duration
	if len(resp.Answer) > 0 {
		ttl = time.Duration(resp.Answer[0].Header().Ttl) * time.Second
	} else if resp.Rcode == dns.RcodeNameError {
		ttl = 60 * time.Second
	} else {
		ttl = 30 * time.Second
	}

	cache.Lock()
	cache.data[cacheKey] = cacheEntry{
		msg:      resp,
		expireAt: time.Now().Add(ttl),
	}
	cache.Unlock()
	log.Printf("Stored %s in cache with TTL %s", cacheKey, ttl)

	w.WriteMsg(resp)
}

func resolveDoH(query *dns.Msg) (*dns.Msg, error) {
	raw, _ := query.Pack()
	encoded := base64.RawURLEncoding.EncodeToString(raw)

	req, _ := http.NewRequest("GET", dohURL+"?dns="+encoded, nil)
	req.Header.Set("Accept", "application/dns-message")

	// SOCKS5 Dialer
	dialer, err := proxy.SOCKS5("tcp", socksServer, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{}
	transport.Dial = dialer.Dial

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
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
