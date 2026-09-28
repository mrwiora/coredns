package sazu

import (
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// Authenticated denial of existence with NSEC (RFC 4034 §4, RFC 4035
// §2.3). The server never signs, so it can't synthesize NSEC records at
// answer time: the zone owner's signer computes and signs the complete
// chain as part of every full-zone push (BuildNSECChain), the way an
// offline signer such as dnssec-signzone does, and the server serves the
// right stored record for each negative answer (lookup.go).

// CanonicalCompare orders a and b per RFC 4034 §6.1 ("Canonical DNS Name
// Order"): labels compare from most-significant (rightmost) to least,
// case-insensitively (US-ASCII only), with a name that is a proper
// right-hand suffix of another sorting first. Returns a value whose sign
// indicates order, the way strings.Compare's does (not necessarily
// exactly -1/0/1).
//
// Implemented over dns.SplitDomainName's label strings rather than
// decoded wire bytes -- correct for the plain ASCII hostnames SAZU zones
// actually contain, but not a general-purpose implementation: a label
// using a \DDD numeric escape (RFC 1035 §5.1) for a byte outside normal
// printable ASCII compares by its literal escaped text, not the byte it
// represents, which no real SAZU deployment will ever need to push.
func CanonicalCompare(a, b string) int {
	la, lb := reversedLabels(a), reversedLabels(b)
	for i := 0; i < len(la) && i < len(lb); i++ {
		if c := strings.Compare(la[i], lb[i]); c != 0 {
			return c
		}
	}
	return len(la) - len(lb)
}

func reversedLabels(name string) []string {
	labels := dns.SplitDomainName(dns.Fqdn(name))
	out := make([]string, len(labels))
	for i, l := range labels {
		out[len(labels)-1-i] = strings.ToLower(l)
	}
	return out
}

// SortNamesCanonically sorts names in place in RFC 4034 §6.1 order.
func SortNamesCanonically(names []string) {
	sort.Slice(names, func(i, j int) bool { return CanonicalCompare(names[i], names[j]) < 0 })
}

// denialTTL is the TTL of a zone's NSEC, NSEC3 and NSEC3PARAM records:
// the lesser of the SOA's own TTL and its MINIMUM field (RFC 9077 §3.1).
func denialTTL(soa *dns.SOA) uint32 {
	if soa.Minttl < soa.Hdr.Ttl {
		return soa.Minttl
	}
	return soa.Hdr.Ttl
}

// BuildNSECChain builds the NSEC chain (RFC 4034 §4, RFC 4035 §2.3) for
// a full push's content adds: one NSEC per authoritative name and
// delegation point, in canonical order, circular. Names below a zone cut
// (glue) are left out, and the bitmap at a cut lists only NS, DS (if
// present), NSEC and RRSIG. The records still need signing along with
// the rest of the push.
func BuildNSECChain(soa *dns.SOA, adds []dns.RR) []dns.RR {
	apex := strings.ToLower(dns.Fqdn(soa.Hdr.Name))
	typesByName, _ := denialTypes(apex, adds)

	names := make([]string, 0, len(typesByName))
	for name := range typesByName {
		names = append(names, name)
	}
	SortNamesCanonically(names)

	ttl := denialTTL(soa)
	out := make([]dns.RR, 0, len(names))
	for i, name := range names {
		types := typesByName[name]
		types[dns.TypeNSEC] = true
		types[dns.TypeRRSIG] = true
		out = append(out, &dns.NSEC{
			Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: ttl},
			NextDomain: names[(i+1)%len(names)],
			TypeBitMap: sortedTypes(types),
		})
	}
	return out
}

// sortedTypes returns the set's types in ascending order, as a type bitmap
// is packed.
func sortedTypes(types map[uint16]bool) []uint16 {
	out := make([]uint16, 0, len(types))
	for t := range types {
		out = append(out, t)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}
