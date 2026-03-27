package main

import (
	"context"
	"log"
	"shamir0xe/mine-dns/dependencies"
	"shamir0xe/mine-dns/services"

	"github.com/miekg/dns"
)

func main() {
	log.Println("Starting MineDNS...")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := dependencies.NewViperConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	cache := dependencies.NewCache[dns.Msg](ctx, cfg.Sub("cache"))

	resolver := services.NewResolver(cfg, cache)

	dns.HandleFunc(".", resolver.HandleDNS)

	server := &dns.Server{
		Addr: cfg.GetString("dns-server.addr"),
		Net:  cfg.GetString("dns-server.net"),
	}

	log.Printf("DNS server started on %s - %s\n", server.Addr, server.Net)
	log.Fatal(server.ListenAndServe())
}
