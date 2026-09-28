package sazu

import (
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// Authoritative answering over a zone's stored, pre-signed content:
// RFC 1034 §4.3.2 (the lookup algorithm: exact match, CNAME, zone cuts
// and referrals, wildcards), RFC 4592 (wildcards), RFC 6672 (DNAME),
// RFC 2308 (negative answers), and RFC 4035 §3.1 / RFC 5155 §7.2 (the
// DNSSEC records a validating resolver needs, including NSEC/NSEC3
// proofs for NXDOMAIN, NODATA, wildcard answers and unsigned
// delegations). The server never signs: every RRSIG, NSEC and NSEC3
// record it returns is one the zone's owner pushed.

// maxChase bounds CNAME/DNAME chasing within one zone.
const maxChase = 8

// Answer is the result of looking a question up in one zone.
type Answer struct {
	Rcode         int
	Authoritative bool
	Answer        []dns.RR
	Ns            []dns.RR
	Extra         []dns.RR
}

// Answer looks qname/qtype up in z. do asks for DNSSEC records (the
// query's DO bit, RFC 3225).
func (z *ZoneData) Answer(qname string, qtype uint16, do bool) Answer {
	z.mu.RLock()
	defer z.mu.RUnlock()
	v := &zoneView{z: z, do: do}
	return v.answer(strings.ToLower(dns.Fqdn(qname)), qtype)
}

// zoneView is one query's read-only view of a zone; the caller holds
// z.mu for reading.
type zoneView struct {
	z  *ZoneData
	do bool

	names map[string]bool // every existing name, empty non-terminals included (lazy)
}

func (v *zoneView) answer(qname string, qtype uint16) Answer {
	res := Answer{Rcode: dns.RcodeSuccess, Authoritative: true}
	for hop := 0; hop < maxChase; hop++ {
		if !dns.IsSubDomain(v.z.Origin, qname) {
			return res // chased out of the zone: the answer so far is complete
		}

		// Zone cut between the apex and qname: a referral (RFC 1034
		// §4.3.2 step 3b), except that the DS RRset at a cut belongs to
		// this (the parent) zone and is answered here (RFC 4035 §3.1.4.1).
		if cut := v.cut(qname); cut != "" && !(qname == cut && qtype == dns.TypeDS) {
			v.referral(&res, cut)
			return res
		}

		// DNAME at a proper ancestor of qname (RFC 6672 §3.3).
		if owner, dname := v.dnameAbove(qname); dname != nil {
			res.Answer = append(res.Answer, v.withSigs(owner, dns.TypeDNAME, []dns.RR{dname})...)
			target := strings.TrimSuffix(qname, owner) + strings.ToLower(dname.Target)
			res.Answer = append(res.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: dname.Hdr.Ttl},
				Target: target,
			})
			qname = target
			continue
		}

		if v.exists(qname) {
			if rrs := v.rrset(qname, qtype); len(rrs) > 0 {
				res.Answer = append(res.Answer, v.withSigs(qname, qtype, rrs)...)
				return res
			}
			if qtype != dns.TypeCNAME {
				if cname := v.rrset(qname, dns.TypeCNAME); len(cname) > 0 {
					res.Answer = append(res.Answer, v.withSigs(qname, dns.TypeCNAME, cname)...)
					qname = strings.ToLower(cname[0].(*dns.CNAME).Target)
					continue
				}
			}
			v.negative(&res)
			if v.do {
				res.Ns = append(res.Ns, v.nodataProof(qname)...)
			}
			return res
		}

		// qname doesn't exist: a wildcard at its closest encloser may
		// synthesize the answer (RFC 4592 §3.3.1).
		ce := v.closestEncloser(qname)
		wildcard := "*." + ce
		if v.exists(wildcard) {
			if rrs := v.rrset(wildcard, qtype); len(rrs) > 0 {
				res.Answer = append(res.Answer, v.synthesize(qname, wildcard, qtype, rrs)...)
				if v.do {
					res.Ns = append(res.Ns, v.wildcardAnswerProof(qname, ce)...)
				}
				return res
			}
			if qtype != dns.TypeCNAME {
				if cname := v.rrset(wildcard, dns.TypeCNAME); len(cname) > 0 {
					res.Answer = append(res.Answer, v.synthesize(qname, wildcard, dns.TypeCNAME, cname)...)
					if v.do {
						res.Ns = append(res.Ns, v.wildcardAnswerProof(qname, ce)...)
					}
					qname = strings.ToLower(cname[0].(*dns.CNAME).Target)
					continue
				}
			}
			v.negative(&res)
			if v.do {
				res.Ns = append(res.Ns, v.wildcardNodataProof(qname, ce, wildcard)...)
			}
			return res
		}

		res.Rcode = dns.RcodeNameError
		v.negative(&res)
		if v.do {
			res.Ns = append(res.Ns, v.nxdomainProof(qname, ce)...)
		}
		return res
	}
	return res
}

// negative adds the zone's SOA to the authority section, with the TTL a
// negative answer may be cached for: the lesser of the SOA's own TTL and
// its MINIMUM field (RFC 2308 §3, §5).
func (v *zoneView) negative(res *Answer) {
	if v.z.soa == nil {
		return
	}
	ttl := v.z.soa.Hdr.Ttl
	if v.z.soa.Minttl < ttl {
		ttl = v.z.soa.Minttl
	}
	soa := dns.Copy(v.z.soa)
	soa.Header().Ttl = ttl
	res.Ns = append(res.Ns, soa)
	if v.do {
		for _, sig := range v.sigs(v.z.Origin, dns.TypeSOA) {
			sig.Header().Ttl = ttl
			res.Ns = append(res.Ns, sig)
		}
	}
}

// referral fills res with a referral to the child zone at cut: not
// authoritative, the NS RRset in the authority section with the DS RRset
// (or, without one, the proof that there is none) when DNSSEC is asked
// for, and in-zone glue addresses in the additional section (RFC 1034
// §4.3.2, RFC 4035 §3.1.4, RFC 9471).
func (v *zoneView) referral(res *Answer, cut string) {
	res.Authoritative = false
	ns := v.rrset(cut, dns.TypeNS)
	res.Ns = append(res.Ns, ns...)
	if v.do {
		if ds := v.rrset(cut, dns.TypeDS); len(ds) > 0 {
			res.Ns = append(res.Ns, v.withSigs(cut, dns.TypeDS, ds)...)
		} else {
			res.Ns = append(res.Ns, v.nodataProof(cut)...)
		}
	}
	for _, rr := range ns {
		target := strings.ToLower(rr.(*dns.NS).Ns)
		if !dns.IsSubDomain(v.z.Origin, target) {
			continue
		}
		res.Extra = append(res.Extra, v.rrset(target, dns.TypeA)...)
		res.Extra = append(res.Extra, v.rrset(target, dns.TypeAAAA)...)
	}
}

// cut returns the highest zone cut (a non-apex name with an NS RRset) at
// or above qname, or "" if there is none.
func (v *zoneView) cut(qname string) string {
	for _, name := range v.ancestorsBelowApex(qname) {
		if len(v.z.rrsets[name][dns.TypeNS]) > 0 {
			return name
		}
	}
	return ""
}

// dnameAbove returns the DNAME at the proper ancestor of qname closest to
// the apex, if any.
func (v *zoneView) dnameAbove(qname string) (string, *dns.DNAME) {
	candidates := append([]string{v.z.Origin}, v.ancestorsBelowApex(qname)...)
	for _, name := range candidates {
		if name == qname {
			break
		}
		if rrs := v.z.rrsets[name][dns.TypeDNAME]; len(rrs) > 0 {
			if d, ok := rrs[0].(*dns.DNAME); ok {
				return name, d
			}
		}
	}
	return "", nil
}

// ancestorsBelowApex lists the names strictly below the apex on the way
// down to qname, qname included, apex-first.
func (v *zoneView) ancestorsBelowApex(qname string) []string {
	labels := dns.SplitDomainName(qname)
	apexLabels := dns.CountLabel(v.z.Origin)
	var out []string
	for i := len(labels) - apexLabels - 1; i >= 0; i-- {
		out = append(out, dns.Fqdn(strings.Join(labels[i:], ".")))
	}
	return out
}

// rrset returns copies of the RRset name/qtype (for ANY, every RRset at
// the name except RRSIGs).
func (v *zoneView) rrset(name string, qtype uint16) []dns.RR {
	if name == v.z.Origin && qtype == dns.TypeSOA {
		if v.z.soa == nil {
			return nil
		}
		return []dns.RR{dns.Copy(v.z.soa)}
	}
	byType := v.z.rrsets[name]
	var src []dns.RR
	if qtype == dns.TypeANY {
		if name == v.z.Origin && v.z.soa != nil {
			src = append(src, v.z.soa)
		}
		for t, rrs := range byType {
			if t != dns.TypeRRSIG {
				src = append(src, rrs...)
			}
		}
	} else {
		src = byType[qtype]
	}
	out := make([]dns.RR, len(src))
	for i, rr := range src {
		out[i] = dns.Copy(rr)
	}
	return out
}

// sigs returns copies of the RRSIGs at name covering covered.
func (v *zoneView) sigs(name string, covered uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range v.z.rrsets[name][dns.TypeRRSIG] {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == covered {
			out = append(out, dns.Copy(rr))
		}
	}
	return out
}

// withSigs returns rrs, followed by their RRSIGs when DNSSEC is asked
// for. For ANY, the RRSIGs of every returned type.
func (v *zoneView) withSigs(name string, qtype uint16, rrs []dns.RR) []dns.RR {
	if !v.do {
		return rrs
	}
	if qtype != dns.TypeANY {
		return append(rrs, v.sigs(name, qtype)...)
	}
	seen := map[uint16]bool{}
	out := rrs
	for _, rr := range rrs {
		if t := rr.Header().Rrtype; !seen[t] {
			seen[t] = true
			out = append(out, v.sigs(name, t)...)
		}
	}
	return out
}

// synthesize expands the wildcard RRset at wildcard for qname (RFC 4592
// §3.3.1): the records and their RRSIGs, owner rewritten. The RRSIGs'
// Labels field still counts the wildcard's own labels, which is how a
// validator recognizes the expansion.
func (v *zoneView) synthesize(qname, wildcard string, qtype uint16, rrs []dns.RR) []dns.RR {
	out := v.withSigs(wildcard, qtype, rrs)
	for _, rr := range out {
		rr.Header().Name = qname
	}
	return out
}

// exists reports whether name exists in the zone: it owns records, or is
// an empty non-terminal above names that do (RFC 4592 §2.2.2).
func (v *zoneView) exists(name string) bool {
	if v.names == nil {
		v.names = make(map[string]bool)
		v.names[v.z.Origin] = true
		for owner, byType := range v.z.rrsets {
			if !hasRealRecords(byType) {
				continue
			}
			for n := owner; dns.IsSubDomain(v.z.Origin, n); {
				if v.names[n] && n != owner {
					break
				}
				v.names[n] = true
				if n == v.z.Origin {
					break
				}
				i, _ := dns.NextLabel(n, 0)
				n = n[i:]
			}
		}
	}
	return v.names[name]
}

// hasRealRecords reports whether a name's RRsets are anything but NSEC3
// records and their signatures -- NSEC3 owners are hashes, not names of
// the zone's own tree.
func hasRealRecords(byType map[uint16][]dns.RR) bool {
	for t, rrs := range byType {
		if len(rrs) == 0 || t == dns.TypeNSEC3 {
			continue
		}
		if t == dns.TypeRRSIG {
			for _, rr := range rrs {
				if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered != dns.TypeNSEC3 {
					return true
				}
			}
			continue
		}
		return true
	}
	return false
}

// closestEncloser returns the longest existing ancestor of qname (RFC
// 4592 §3.3.1).
func (v *zoneView) closestEncloser(qname string) string {
	for n := qname; ; {
		if v.exists(n) {
			return n
		}
		if n == v.z.Origin || n == "." {
			return v.z.Origin
		}
		i, _ := dns.NextLabel(n, 0)
		n = n[i:]
	}
}

// --- DNSSEC denial of existence -------------------------------------------

func (v *zoneView) nsec3Param() *dns.NSEC3PARAM {
	if rrs := v.z.rrsets[v.z.Origin][dns.TypeNSEC3PARAM]; len(rrs) > 0 {
		p, _ := rrs[0].(*dns.NSEC3PARAM)
		return p
	}
	return nil
}

// nsecOwners returns the owners of the zone's NSEC chain in canonical
// order.
func (v *zoneView) nsecOwners() []string {
	var owners []string
	for name, byType := range v.z.rrsets {
		if len(byType[dns.TypeNSEC]) > 0 {
			owners = append(owners, name)
		}
	}
	SortNamesCanonically(owners)
	return owners
}

// nsec3Hashes returns the owner hashes of the zone's NSEC3 chain in hash
// order.
func (v *zoneView) nsec3Hashes() []string {
	var hashes []string
	for name, byType := range v.z.rrsets {
		if len(byType[dns.TypeNSEC3]) > 0 {
			hashes = append(hashes, strings.ToLower(strings.SplitN(name, ".", 2)[0]))
		}
	}
	sort.Strings(hashes)
	return hashes
}

// proof collects NSEC/NSEC3 records with their RRSIGs, each owner once.
type proof struct {
	v     *zoneView
	out   []dns.RR
	added map[string]bool
}

func (v *zoneView) newProof() *proof { return &proof{v: v, added: map[string]bool{}} }

func (p *proof) add(owner string, t uint16) {
	if owner == "" || p.added[owner] {
		return
	}
	p.added[owner] = true
	p.out = append(p.out, p.v.rrset(owner, t)...)
	p.out = append(p.out, p.v.sigs(owner, t)...)
}

// nsecMatchOrCover adds the NSEC at name, or -- for an empty
// non-terminal, which owns none -- the one covering it.
func (p *proof) nsecMatchOrCover(name string, owners []string) {
	if len(p.v.z.rrsets[name][dns.TypeNSEC]) > 0 {
		p.add(name, dns.TypeNSEC)
		return
	}
	if o, ok := CoveringOwner(name, owners); ok {
		p.add(o, dns.TypeNSEC)
	}
}

func (p *proof) nsecCover(name string, owners []string) {
	if o, ok := CoveringOwner(name, owners); ok {
		p.add(o, dns.TypeNSEC)
	}
}

func (p *proof) nsec3Match(name string, param *dns.NSEC3PARAM) {
	p.add(NSEC3Hash(name, param)+"."+p.v.z.Origin, dns.TypeNSEC3)
}

func (p *proof) nsec3Cover(name string, param *dns.NSEC3PARAM, hashes []string) {
	if h, ok := CoveringHash(NSEC3Hash(name, param), hashes); ok {
		p.add(h+"."+p.v.z.Origin, dns.TypeNSEC3)
	}
}

// nodataProof proves qname exists without the queried type (RFC 4035
// §3.1.3.1, RFC 5155 §7.2.3/§7.2.4); for a delegation, that it has no DS.
func (v *zoneView) nodataProof(qname string) []dns.RR {
	p := v.newProof()
	if param := v.nsec3Param(); param != nil {
		p.nsec3Match(qname, param)
		return p.out
	}
	p.nsecMatchOrCover(qname, v.nsecOwners())
	return p.out
}

// nxdomainProof proves qname doesn't exist and no wildcard could have
// matched it (RFC 4035 §3.1.3.2, RFC 5155 §7.2.2).
func (v *zoneView) nxdomainProof(qname, ce string) []dns.RR {
	p := v.newProof()
	if param := v.nsec3Param(); param != nil {
		hashes := v.nsec3Hashes()
		p.nsec3Match(ce, param)
		p.nsec3Cover(NextCloserName(qname, ce), param, hashes)
		p.nsec3Cover("*."+ce, param, hashes)
		return p.out
	}
	owners := v.nsecOwners()
	p.nsecCover(qname, owners)
	p.nsecCover("*."+ce, owners)
	return p.out
}

// wildcardAnswerProof proves qname itself doesn't exist, for a
// wildcard-synthesized answer (RFC 4035 §3.1.3.3, RFC 5155 §7.2.6).
func (v *zoneView) wildcardAnswerProof(qname, ce string) []dns.RR {
	p := v.newProof()
	if param := v.nsec3Param(); param != nil {
		p.nsec3Cover(NextCloserName(qname, ce), param, v.nsec3Hashes())
		return p.out
	}
	p.nsecCover(qname, v.nsecOwners())
	return p.out
}

// wildcardNodataProof proves qname doesn't exist and the matching
// wildcard lacks the queried type (RFC 4035 §3.1.3.4, RFC 5155 §7.2.5).
func (v *zoneView) wildcardNodataProof(qname, ce, wildcard string) []dns.RR {
	p := v.newProof()
	if param := v.nsec3Param(); param != nil {
		p.nsec3Match(ce, param)
		p.nsec3Cover(NextCloserName(qname, ce), param, v.nsec3Hashes())
		p.nsec3Match(wildcard, param)
		return p.out
	}
	owners := v.nsecOwners()
	p.nsecCover(qname, owners)
	p.nsecMatchOrCover(wildcard, owners)
	return p.out
}
