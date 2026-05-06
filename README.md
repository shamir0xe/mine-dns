# mine-dns

[![Tests](https://github.com/shamir0xe/mine-dns/actions/workflows/test.yml/badge.svg)](https://github.com/shamir0xe/mine-dns/actions/workflows/test.yml)

A local DNS server that forwards queries to Cloudflare DoH (DNS-over-HTTPS) through a SOCKS5 proxy. Supports domain blacklisting, per-domain direct resolution, IP whitelisting, and response caching.

## How it works

1. Incoming DNS query arrives on the configured address (default `:53`)
2. If the source IP is not in `whitelist-subnets`, the query is blackholed
3. If the domain matches `blacklist`, it is redirected to `blackhole-ip`
4. If the domain matches `direct-domains`, it is resolved directly via `direct-dns-servers` in order (fallback on error)
5. Otherwise the query is forwarded to `doh-resolver` over SOCKS5
6. The response is cached and returned to the client

## Configuration

Copy `config.sample.yaml` to `config.yaml` and edit:

```yaml
doh-resolver: "https://cloudflare-dns.com/dns-query"
socks-server: "127.0.0.1:1088"
blackhole-ip: 10.10.10.10

dns-server:
  addr: ":53"
  net: udp

blacklist:
  - instagram
  - facebook

direct-domains:
  - "*.ir"

direct-dns-servers:
  - "178.22.122.100"
  - "185.51.200.2"

whitelist-subnets:
  - "127.0.0.1/32"
  - "192.168.1.0/24"

http:
  timeout: 10s

cache:
  cleanup-interval: 5m
  default-ttl: 3h
  min-ttl: 5m
```

`whitelist-subnets` is required — the server refuses to start if it is empty.

`direct-domains` supports wildcard prefixes: `*.ir` matches any subdomain of `.ir`. Exact entries like `local.test` are also supported.

## Usage

```bash
make deps       # download dependencies
make build      # build binary → ./minedns
make run        # build and run
make test       # run tests with race detector
make build-linux  # cross-compile for Linux amd64
```

The binary reads `config.yaml` from the current working directory.

## Running as a systemd service

```ini
[Unit]
Description=MineDNS
After=network.target

[Service]
ExecStart=/usr/local/bin/minedns
WorkingDirectory=/etc/minedns
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
