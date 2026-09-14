package sazu

import (
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// This file implements RFC 5155 NSEC3, the opt-in alternative to plain
// NSEC (nsec.go) that additionally hides a zone's actual name set from
// enumeration ("zone walking") by proving non-existence over hashed
// owner names instead of the names themselves. nsec.go's own top-of-file
// comment already covers why that privacy property is separate from
// what a *correct* NXDOMAIN/NODATA proof needs, and why plain NSEC was
// implemented first; this is that separate property, for a customer who
// specifically wants it. Selecting it is a push-time decision the
// customer's own signer makes (BuildFullZonePushNSEC3 /
// BuildFullZonePushSplitNSEC3, and sazuctl's "push-zone -nsec3" flag) --
// the server just stores and serves whichever chain it was given,
// exactly as for plain NSEC.
//
// SAZU's split-signing model gives the server one advantage a resolver
// walking an NSEC3 chain blind doesn't have: the server holds every
// pushed name in plaintext in memory regardless of which scheme is in
// use -- hiding names from wire responses never requires hiding them
// from the server that has to serve correct answers. So
// ZoneData.NegativeProof's NSEC3 path computes the closest encloser and
// next-closer name directly from the real name set (reusing nsec.go's
// own ClosestEncloser), then hashes exactly the specific candidate names
// it needs a proof for, rather than needing to guess by hash-ring
// traversal alone the way an external NSEC3 tool would.
//
// Scoped simplification, stated up front rather than left implicit: SAZU
// zones have no delegations of their own (no NS RRset below the apex),
// so there is no per-delegation Opt-Out distinction (RFC 5155 §6) to
// make -- NSEC3Options.OptOut, when set, applies uniformly to every
// record in the chain. A zone that did have its own delegations would
// need per-delegation Opt-Out handling this package doesn't implement.

// NSEC3Options configures BuildNSEC3Chain / BuildFullZonePushNSEC3.
// Iterations and Salt default to RFC 9276's current guidance (zero
// iterations, no salt: NSEC3's iterated hashing turned out to cost real
// resolver/attacker CPU for negligible additional security, so modern
// practice is to stop paying for it) when left at their zero values --
// set them explicitly only to match an existing chain or a specific
// requirement.
type NSEC3Options struct {
	Iterations uint16
	Salt       string // hex-encoded (e.g. "DEADBEEF"), "" for none
	OptOut     bool
}

// NSEC3Hash returns name's RFC 5155 §5 hash under param, lowercase
// (dns.HashName itself returns uppercase; lowercase matches real-world
// zone-file convention and this package's own naming elsewhere).
func NSEC3Hash(name string, param *dns.NSEC3PARAM) string {
	return strings.ToLower(dns.HashName(dns.Fqdn(name), param.Hash, param.Iterations, param.Salt))
}

// BuildNSEC3Chain is BuildNSECChain's RFC 5155 equivalent: one NSEC3 RR
// per distinct owner name in adds, ordered by hash value (RFC 5155's
// hash order and RFC 4034's canonical name order are both total orders
// over a fixed alphabet compared byte-by-byte; since every name hashes
// to the same 20-byte SHA-1 output, plain string comparison of the
// resulting fixed-length base32hex text sorts the chain correctly),
// plus the NSEC3PARAM record identifying the hash parameters used.
// TTL, like BuildNSECChain's, is the zone's SOA minimum (RFC 5155 §3
// makes the same requirement RFC 4034 §4 makes for NSEC).
func BuildNSEC3Chain(soa *dns.SOA, adds []dns.RR, opts NSEC3Options) []dns.RR {
	apex := dns.Fqdn(soa.Hdr.Name)
	param := &dns.NSEC3PARAM{
		Hdr:        dns.RR_Header{Name: apex, Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: soa.Minttl},
		Hash:       dns.SHA1,
		Iterations: opts.Iterations,
		SaltLength: uint8(len(opts.Salt)) / 2,
		Salt:       opts.Salt,
	}

	typesByName := map[string]map[uint16]bool{strings.ToLower(apex): {}}
	for _, rr := range adds {
		name := strings.ToLower(dns.Fqdn(rr.Header().Name))
		if typesByName[name] == nil {
			typesByName[name] = make(map[uint16]bool)
		}
		typesByName[name][rr.Header().Rrtype] = true
	}
	typesByName[strings.ToLower(apex)][dns.TypeNSEC3PARAM] = true

	type hashedName struct{ hash, name string }
	hashed := make([]hashedName, 0, len(typesByName))
	for name := range typesByName {
		hashed = append(hashed, hashedName{hash: NSEC3Hash(name, param), name: name})
	}
	sort.Slice(hashed, func(i, j int) bool { return hashed[i].hash < hashed[j].hash })

	var flags uint8
	if opts.OptOut {
		flags = 1
	}

	out := make([]dns.RR, 0, len(hashed)+1)
	for i, h := range hashed {
		types := typesByName[h.name]
		types[dns.TypeRRSIG] = true
		bitmap := make([]uint16, 0, len(types))
		for t := range types {
			bitmap = append(bitmap, t)
		}
		sort.Slice(bitmap, func(a, b int) bool { return bitmap[a] < bitmap[b] }) // packDataNsec requires ascending order

		out = append(out, &dns.NSEC3{
			Hdr:        dns.RR_Header{Name: h.hash + "." + apex, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: soa.Minttl},
			Hash:       dns.SHA1,
			Flags:      flags,
			Iterations: opts.Iterations,
			SaltLength: param.SaltLength,
			Salt:       opts.Salt,
			HashLength: 20, // SHA-1: RFC 5155 defines no other hash algorithm yet
			NextDomain: hashed[(i+1)%len(hashed)].hash,
			TypeBitMap: bitmap,
		})
	}
	return append(out, param)
}

// NextCloserName returns the "next closer name" (RFC 5155 §7.2.1) on the
// path from closestEncloser to qname: closestEncloser itself, plus
// exactly one more label toward qname. Well-defined whenever
// closestEncloser is a true suffix of qname with strictly fewer labels,
// which is always the case for the closest encloser NegativeProof's
// NSEC3 path computes (ClosestEncloser never returns qname itself for a
// name proven not to exist).
func NextCloserName(qname, closestEncloser string) string {
	qLabels := dns.SplitDomainName(dns.Fqdn(qname))
	ceLabels := len(dns.SplitDomainName(dns.Fqdn(closestEncloser)))
	keep := ceLabels + 1
	if keep > len(qLabels) {
		keep = len(qLabels)
	}
	return dns.Fqdn(strings.Join(qLabels[len(qLabels)-keep:], "."))
}

// CoveringHash returns which member of sortedHashes (already ascending,
// deduplicated) covers hash: the largest entry strictly less than hash,
// or -- since the NSEC3 chain is circular, same as NSEC's -- the last
// entry if hash precedes all of them. Mirrors nsec.go's CoveringOwner,
// operating on plain hash strings (ascending lexical order on these
// fixed-length base32hex values is the same order HashName's outputs
// need for the chain itself) instead of RFC 4034 canonical name order.
func CoveringHash(hash string, sortedHashes []string) (string, bool) {
	if len(sortedHashes) == 0 {
		return "", false
	}
	best := -1
	for i, h := range sortedHashes {
		if h < hash {
			best = i
			continue
		}
		break
	}
	if best == -1 {
		return sortedHashes[len(sortedHashes)-1], true
	}
	return sortedHashes[best], true
}
