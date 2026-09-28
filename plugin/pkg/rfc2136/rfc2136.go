// Package rfc2136 implements the parts of RFC 2136 DNS UPDATE processing
// that don't depend on how a plugin stores its zone: the prescan of the
// prerequisite and update sections, prerequisite evaluation, and the RR
// and serial comparisons they rely on.
package rfc2136

import (
	"strings"

	"github.com/miekg/dns"
)

// Zone is the read access prerequisite evaluation needs.
type Zone interface {
	// NameInUse reports whether name owns at least one RR (RFC 2136
	// §2.4.4).
	NameInUse(name string) bool
	// RRset returns the RRs of the RRset name/rrtype, or none.
	RRset(name string, rrtype uint16) []dns.RR
}

// Policy lets a plugin refuse an RR for its own reasons during a prescan,
// after the RFC 2136 checks on it have passed. It returns
// dns.RcodeSuccess to accept the RR, or the RCODE to reject it with. A nil
// Policy accepts everything.
type Policy func(dns.RR) int

func (p Policy) check(rr dns.RR) int {
	if p == nil {
		return dns.RcodeSuccess
	}
	return p(rr)
}

// CanonicalName returns name as a lowercase FQDN.
func CanonicalName(name string) string {
	return strings.ToLower(dns.CanonicalName(name))
}

// InZone reports whether name is at or below origin.
func InZone(origin, name string) bool {
	return dns.IsSubDomain(CanonicalName(origin), CanonicalName(name))
}

// KnownType reports whether miekg/dns knows rrtype.
func KnownType(rrtype uint16) bool {
	_, ok := dns.TypeToRR[rrtype]
	return ok
}

// IsQueryMetaType reports whether rrtype only exists in queries or
// transaction records, never as zone data.
func IsQueryMetaType(rrtype uint16) bool {
	switch rrtype {
	case dns.TypeANY, dns.TypeAXFR, dns.TypeIXFR, dns.TypeMAILA, dns.TypeMAILB,
		dns.TypeOPT, dns.TypeTKEY, dns.TypeTSIG:
		return true
	default:
		return false
	}
}

// CNAMECompatible reports whether an RR of rrtype may share an owner name
// with a CNAME: only RRSIG and NSEC may (RFC 2181 §10.1, RFC 4035 §2.5).
func CNAMECompatible(rrtype uint16) bool {
	return rrtype == dns.TypeCNAME || rrtype == dns.TypeRRSIG || rrtype == dns.TypeNSEC
}

// SerialGreater reports whether SOA serial a is greater than b in RFC 1982
// serial arithmetic. The half-space value, which RFC 1982 leaves
// undefined, is not greater.
func SerialGreater(a, b uint32) bool {
	return a != b && a-b < 1<<31
}

// SameRR reports whether a and b are the same RR: same owner, type and
// RDATA. TTL and class are ignored, since UPDATE deletes and prerequisites
// carry class NONE or ANY and TTL 0 (RFC 2136 §2.4, §2.5).
func SameRR(a, b dns.RR) bool {
	if a == nil || b == nil {
		return false
	}
	left, right := dns.Copy(a), dns.Copy(b)
	if left == nil || right == nil {
		return false
	}
	left.Header().Class = dns.ClassINET
	right.Header().Class = dns.ClassINET
	return dns.IsDuplicate(left, right)
}

// SameRRset reports whether have and want hold the same RRs, as sets.
func SameRRset(have, want []dns.RR) bool {
	have, want = unique(have), unique(want)
	if len(have) != len(want) {
		return false
	}
	used := make([]bool, len(have))
	for _, w := range want {
		found := false
		for i, h := range have {
			if !used[i] && SameRR(h, w) {
				used[i], found = true, true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func unique(rrs []dns.RR) []dns.RR {
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		dup := false
		for _, u := range out {
			if SameRR(u, rr) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, rr)
		}
	}
	return out
}

func validPrerequisiteType(rrtype uint16, allowAny bool) bool {
	if !KnownType(rrtype) || rrtype == dns.TypeNone {
		return false
	}
	if rrtype == dns.TypeANY {
		return allowAny
	}
	return !IsQueryMetaType(rrtype)
}

// prescanPrerequisite checks one prerequisite RR's form (RFC 2136 §3.2.1).
// It relies on Rdlength as unpacked from the wire.
func prescanPrerequisite(zone string, rr dns.RR, zclass uint16, policy Policy) int {
	if rr == nil {
		return dns.RcodeFormatError
	}
	h := rr.Header()
	if h.Ttl != 0 {
		return dns.RcodeFormatError
	}
	if !InZone(zone, h.Name) {
		return dns.RcodeNotZone
	}
	if rcode := policy.check(rr); rcode != dns.RcodeSuccess {
		return rcode
	}
	switch h.Class {
	case dns.ClassANY, dns.ClassNONE:
		if h.Rdlength != 0 || !validPrerequisiteType(h.Rrtype, true) {
			return dns.RcodeFormatError
		}
	case zclass:
		if !validPrerequisiteType(h.Rrtype, false) {
			return dns.RcodeFormatError
		}
	default:
		return dns.RcodeFormatError
	}
	return dns.RcodeSuccess
}

// PrescanPrerequisites checks the form of every prerequisite (RFC 2136
// §3.2.1) without evaluating any, for a caller that evaluates them later
// with CheckPrerequisites. It returns the RCODE and the offending RR.
func PrescanPrerequisites(zone string, prereqs []dns.RR, zclass uint16, policy Policy) (int, dns.RR) {
	for _, rr := range prereqs {
		if rcode := prescanPrerequisite(zone, rr, zclass, policy); rcode != dns.RcodeSuccess {
			return rcode, rr
		}
	}
	return dns.RcodeSuccess, nil
}

type rrsetKey struct {
	name   string
	rrtype uint16
}

// CheckPrerequisites prescans and evaluates the prerequisite section
// against z in the order of RFC 2136 §3.2, returning dns.RcodeSuccess or
// the RCODE of the first failure and the prerequisite that failed. A
// value-dependent prerequisite (§2.4.2) must match its RRset exactly.
func CheckPrerequisites(zone string, prereqs []dns.RR, zclass uint16, z Zone, policy Policy) (int, dns.RR) {
	valueDependent := make(map[rrsetKey][]dns.RR)
	var order []rrsetKey
	for _, rr := range prereqs {
		if rcode := prescanPrerequisite(zone, rr, zclass, policy); rcode != dns.RcodeSuccess {
			return rcode, rr
		}
		h := rr.Header()
		switch h.Class {
		case dns.ClassANY:
			if h.Rrtype == dns.TypeANY {
				if !z.NameInUse(h.Name) {
					return dns.RcodeNameError, rr
				}
			} else if len(z.RRset(h.Name, h.Rrtype)) == 0 {
				return dns.RcodeNXRrset, rr
			}
		case dns.ClassNONE:
			if h.Rrtype == dns.TypeANY {
				if z.NameInUse(h.Name) {
					return dns.RcodeYXDomain, rr
				}
			} else if len(z.RRset(h.Name, h.Rrtype)) != 0 {
				return dns.RcodeYXRrset, rr
			}
		default:
			key := rrsetKey{name: CanonicalName(h.Name), rrtype: h.Rrtype}
			if _, seen := valueDependent[key]; !seen {
				order = append(order, key)
			}
			valueDependent[key] = append(valueDependent[key], rr)
		}
	}
	for _, key := range order {
		want := valueDependent[key]
		if !SameRRset(z.RRset(key.name, key.rrtype), want) {
			return dns.RcodeNXRrset, want[0]
		}
	}
	return dns.RcodeSuccess, nil
}

// PrescanUpdates checks every RR of the update section (RFC 2136
// §3.4.1.3): in the zone (else NOTZONE), a known type, and one of the
// class, TTL and RDATA forms of §2.5 (else FORMERR); then policy. It
// returns the RCODE and the offending RR. It relies on Rdlength as
// unpacked from the wire.
func PrescanUpdates(zone string, updates []dns.RR, zclass uint16, policy Policy) (int, dns.RR) {
	for _, rr := range updates {
		if rr == nil {
			return dns.RcodeFormatError, rr
		}
		h := rr.Header()
		if !InZone(zone, h.Name) {
			return dns.RcodeNotZone, rr
		}
		if !KnownType(h.Rrtype) || h.Rrtype == dns.TypeNone {
			return dns.RcodeFormatError, rr
		}
		switch h.Class {
		case zclass:
			if IsQueryMetaType(h.Rrtype) {
				return dns.RcodeFormatError, rr
			}
		case dns.ClassANY:
			if h.Ttl != 0 || h.Rdlength != 0 || IsQueryMetaType(h.Rrtype) && h.Rrtype != dns.TypeANY {
				return dns.RcodeFormatError, rr
			}
		case dns.ClassNONE:
			if h.Ttl != 0 || h.Rrtype == dns.TypeANY || IsQueryMetaType(h.Rrtype) {
				return dns.RcodeFormatError, rr
			}
		default:
			return dns.RcodeFormatError, rr
		}
		if rcode := policy.check(rr); rcode != dns.RcodeSuccess {
			return rcode, rr
		}
	}
	return dns.RcodeSuccess, nil
}
