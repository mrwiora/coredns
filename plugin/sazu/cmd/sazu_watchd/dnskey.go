package main

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// DNSKEYFetcher reports which DNSKEY key tags a zone is currently
// serving at its apex -- satisfied by liveDNSKEYFetcher (a real DNS
// query) or a fake in tests, mirroring how sazu.ChainValidator lets
// checkOnce's chain-of-trust re-check run without real network access
// in watch_test.go.
type DNSKEYFetcher interface {
	FetchServedDNSKEYTags(zone string) (map[uint16]bool, error)
}

// liveDNSKEYFetcher queries a zone's own current authoritative servers
// directly for its DNSKEY RRset -- an ordinary, unauthenticated query,
// the same kind §11's NS/DS watch loop already makes. This is
// deliberately not chain.go's Validator: that performs a full,
// cryptographically anchored root-to-parent walk for a first-contact or
// rollover push to trust a *new* key, which is real per-request latency
// this check has no reason to pay -- a ZSK's continued presence is a
// liveness/drift check against what's actually being served, not a
// re-validation of trust that already happened once, at registration.
type liveDNSKEYFetcher struct {
	Timeout time.Duration
}

// FetchServedDNSKEYTags looks up zone's current nameservers via the
// ordinary system resolver, then queries one directly for its DNSKEY
// RRset. Fails on the first nameserver/address that answers -- there is
// deliberately no retry-every-server loop here (unlike chain.go's
// Validator, which fails closed on a security check): a single
// reachable answer is exactly as informative as a security-critical
// query would need many for, since a wrong or missing answer here only
// ever produces a debounced advisory alert, never blocks a push.
func (f liveDNSKEYFetcher) FetchServedDNSKEYTags(zone string) (map[uint16]bool, error) {
	zone = dns.Fqdn(zone)
	nsHosts, err := net.LookupNS(zone)
	if err != nil {
		return nil, fmt.Errorf("looking up %s's nameservers: %w", zone, err)
	}
	if len(nsHosts) == 0 {
		return nil, fmt.Errorf("no nameservers found for %s", zone)
	}

	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeDNSKEY)
	m.RecursionDesired = false
	client := &dns.Client{Timeout: f.Timeout}

	var lastErr error
	for _, ns := range nsHosts {
		addrs, err := net.LookupHost(ns.Host)
		if err != nil {
			lastErr = err
			continue
		}
		for _, addr := range addrs {
			resp, _, err := client.Exchange(m, net.JoinHostPort(addr, "53"))
			if err != nil {
				lastErr = err
				continue
			}
			tags := make(map[uint16]bool, len(resp.Answer))
			for _, rr := range resp.Answer {
				if key, ok := rr.(*dns.DNSKEY); ok {
					tags[key.KeyTag()] = true
				}
			}
			return tags, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no nameserver for %s answered", zone)
	}
	return nil, fmt.Errorf("querying %s's DNSKEY RRset: %w", zone, lastErr)
}
