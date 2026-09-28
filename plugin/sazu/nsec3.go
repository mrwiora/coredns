package sazu

import (
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// Authenticated denial of existence with hashed owner names (RFC 5155).
// As with NSEC, the zone owner's signer builds and signs the complete
// chain (BuildNSEC3Chain) and the server serves the stored records; it
// knows the zone's real names, so it hashes exactly the names a proof
// needs (lookup.go).

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

// BuildNSEC3Chain builds the NSEC3 chain and NSEC3PARAM record (RFC
// 5155 §7.1) for a full push's content adds: one NSEC3 per authoritative
// name, delegation point and empty non-terminal, in hash order, circular.
// Names below a zone cut (glue) are left out. With OptOut, delegations
// without a DS (and empty non-terminals only they create) are left out
// too, and every record carries the Opt-Out flag (RFC 5155 §6). An NSEC3's
// bitmap lists RRSIG only when its name owns signed RRsets: not for an
// empty non-terminal or a delegation without DS.
func BuildNSEC3Chain(soa *dns.SOA, adds []dns.RR, opts NSEC3Options) []dns.RR {
	apex := strings.ToLower(dns.Fqdn(soa.Hdr.Name))
	ttl := denialTTL(soa)
	param := &dns.NSEC3PARAM{
		Hdr:        dns.RR_Header{Name: apex, Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: ttl},
		Hash:       dns.SHA1,
		Iterations: opts.Iterations,
		SaltLength: uint8(len(opts.Salt)) / 2,
		Salt:       opts.Salt,
	}

	typesByName, cuts := denialTypes(apex, adds)
	typesByName[apex][dns.TypeNSEC3PARAM] = true
	insecure := func(name string) bool { return cuts[name] && !typesByName[name][dns.TypeDS] }
	if opts.OptOut {
		for name := range typesByName {
			if insecure(name) {
				delete(typesByName, name)
			}
		}
	}
	signed := make(map[string]bool, len(typesByName))
	for name := range typesByName {
		signed[name] = !insecure(name)
	}
	// Empty non-terminals between each name and the apex.
	for name := range signed {
		for n := name; n != apex; {
			i, _ := dns.NextLabel(n, 0)
			n = n[i:]
			if _, ok := typesByName[n]; ok || n == "" {
				break
			}
			typesByName[n] = map[uint16]bool{}
		}
	}

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
		if signed[h.name] {
			types[dns.TypeRRSIG] = true
		}
		out = append(out, &dns.NSEC3{
			Hdr:        dns.RR_Header{Name: h.hash + "." + apex, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: ttl},
			Hash:       dns.SHA1,
			Flags:      flags,
			Iterations: opts.Iterations,
			SaltLength: param.SaltLength,
			Salt:       opts.Salt,
			HashLength: 20, // SHA-1, the only hash RFC 5155 defines
			NextDomain: hashed[(i+1)%len(hashed)].hash,
			TypeBitMap: sortedTypes(types),
		})
	}
	return append(out, param)
}

// NextCloserName returns the "next closer name" (RFC 5155 §7.2.1) on the
// path from closestEncloser to qname: closestEncloser itself, plus
// exactly one more label toward qname. Well-defined whenever
// closestEncloser is a true suffix of qname with strictly fewer labels,
// which holds for the closest encloser of a name that doesn't exist.
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
