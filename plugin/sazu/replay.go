package sazu

import (
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DefaultMaxSIG0Lifetime is the longest SIG(0) validity window
// (expiration - inception) serveUpdate accepts: one hour plus five
// minutes of clock-skew allowance. sazuctl signs with inception one
// minute in the past and expiration one hour in the future, comfortably
// inside it. This only bounds how long a captured message stays
// cryptographically valid; replay itself is prevented by the SOA serial
// and version rules (see version.go).
const DefaultMaxSIG0Lifetime = time.Hour + 5*time.Minute

// apexSOA returns the Add-shaped SOA at zone's apex among ops, if any.
func apexSOA(ops []dns.RR, zone string) *dns.SOA {
	for _, rr := range ops {
		soa, ok := rr.(*dns.SOA)
		if ok && soa.Hdr.Rdlength > 0 && strings.EqualFold(soa.Hdr.Name, dns.Fqdn(zone)) {
			return soa
		}
	}
	return nil
}
