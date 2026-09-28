package sazu

import (
	"strings"

	"github.com/miekg/dns"
)

// Zone cuts (RFC 1034 §4.2.1). A name below the apex that owns an NS
// RRset delegates everything at and below it to a child zone. Of the
// records a zone holds at and below a cut, only the DS RRset (and the
// NSEC record) at the cut itself are the zone's own authoritative data;
// the NS RRset at the cut and any address records below it (glue) are
// not, and are left unsigned (RFC 4035 §2.2) and out of the denial
// chain (RFC 4035 §2.3, RFC 5155 §7.1).

// zoneApex returns the owner of the SOA record in rrs, or "" if there is
// none.
func zoneApex(rrs []dns.RR) string {
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeSOA {
			return strings.ToLower(dns.Fqdn(rr.Header().Name))
		}
	}
	return ""
}

// zoneCuts returns the delegation points among rrs: every name strictly
// below apex that owns an NS record.
func zoneCuts(apex string, rrs []dns.RR) map[string]bool {
	cuts := make(map[string]bool)
	if apex == "" {
		return cuts
	}
	for _, rr := range rrs {
		h := rr.Header()
		name := strings.ToLower(dns.Fqdn(h.Name))
		if h.Rrtype == dns.TypeNS && name != apex && dns.IsSubDomain(apex, name) {
			cuts[name] = true
		}
	}
	return cuts
}

// belowCut reports whether name lies strictly below one of cuts.
func belowCut(name, apex string, cuts map[string]bool) bool {
	if len(cuts) == 0 {
		return false
	}
	name = strings.ToLower(dns.Fqdn(name))
	for n := name; n != apex && n != "."; {
		i, _ := dns.NextLabel(n, 0)
		n = n[i:]
		if cuts[n] {
			return true
		}
	}
	return false
}

// isAuthoritativeRRset reports whether the RRset name/rtype is the
// zone's own authoritative data -- what RFC 4035 §2.2 requires signed.
func isAuthoritativeRRset(name string, rtype uint16, apex string, cuts map[string]bool) bool {
	if belowCut(name, apex, cuts) {
		return false
	}
	if cuts[strings.ToLower(dns.Fqdn(name))] {
		return rtype == dns.TypeDS || rtype == dns.TypeNSEC
	}
	return true
}

// denialTypes maps every name the zone's denial chain describes to the
// types present there (RRSIG, NSEC and NSEC3 excluded; the chain
// builders add those): names below a cut are left out, a cut lists only
// NS and DS, and the apex always lists DNSKEY (a SAZU zone always has
// one, whether or not this particular push carries it).
func denialTypes(apex string, adds []dns.RR) (types map[string]map[uint16]bool, cuts map[string]bool) {
	cuts = zoneCuts(apex, adds)
	types = map[string]map[uint16]bool{apex: {dns.TypeDNSKEY: true}}
	for _, rr := range adds {
		h := rr.Header()
		name := strings.ToLower(dns.Fqdn(h.Name))
		switch h.Rrtype {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
			continue
		}
		if belowCut(name, apex, cuts) {
			continue
		}
		if cuts[name] && h.Rrtype != dns.TypeNS && h.Rrtype != dns.TypeDS {
			continue
		}
		if types[name] == nil {
			types[name] = make(map[uint16]bool)
		}
		types[name][h.Rrtype] = true
	}
	return types, cuts
}
