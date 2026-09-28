package sazu

import (
	"fmt"

	"github.com/miekg/dns"
)

// EvaluatePrerequisites checks RFC 2136 §2.4's five prerequisite forms
// against zone's current content, in order, failing on the first one not
// satisfied. Distinguishing the five forms relies on Class and Rdlength
// exactly as they appear on the wire -- correct for prereqs as unpacked
// from a received message (which is the only place this is meant to be
// called from), not for freshly-constructed-in-Go RRs, whose zero-value
// Rdlength would be indistinguishable from a real value-independent
// prerequisite.
//
// Returns the RFC 2136-appropriate rcode for the first failure (matching
// §2.6's rcode table), a §12 SAZU status code if this specific failure has
// one (currently just the SOA-serial staleness guard's ERR_STALE_SERIAL;
// "" for every other, more generic RFC 2136 prerequisite failure), and a
// human-readable reason -- or (dns.RcodeSuccess, "", nil) if every
// prerequisite holds.
func EvaluatePrerequisites(zone *ZoneData, prereqs []dns.RR, zclass uint16) (int, string, error) {
	for _, rr := range prereqs {
		h := rr.Header()
		switch {
		case h.Class == dns.ClassANY && h.Rrtype == dns.TypeANY && h.Rdlength == 0:
			// §2.4.4 Name is in use.
			if !zone.NameExists(h.Name) {
				return dns.RcodeNameError, "", fmt.Errorf("name %s is not in use", h.Name)
			}
		case h.Class == dns.ClassNONE && h.Rrtype == dns.TypeANY && h.Rdlength == 0:
			// §2.4.5 Name is not in use.
			if zone.NameExists(h.Name) {
				return dns.RcodeYXDomain, "", fmt.Errorf("name %s is already in use", h.Name)
			}
		case h.Class == dns.ClassANY && h.Rdlength == 0:
			// §2.4.1 RRset exists (value-independent).
			if len(zone.Lookup(h.Name, h.Rrtype)) == 0 {
				return dns.RcodeNXRrset, "", fmt.Errorf("rrset %s/%s does not exist", h.Name, dns.TypeToString[h.Rrtype])
			}
		case h.Class == dns.ClassNONE && h.Rdlength == 0:
			// §2.4.3 RRset does not exist.
			if len(zone.Lookup(h.Name, h.Rrtype)) != 0 {
				return dns.RcodeYXRrset, "", fmt.Errorf("rrset %s/%s exists but must not", h.Name, dns.TypeToString[h.Rrtype])
			}
		case h.Class == zclass:
			// §2.4.2 RRset exists (value-dependent) -- the SOA-serial
			// staleness guard (BuildFullZonePush's previousSOA parameter)
			// uses exactly this form, always against the apex SOA, which
			// is what lets this branch tell that specific, common case
			// apart from a generic value-dependent prerequisite against
			// some other RRset.
			existing := zone.Lookup(h.Name, h.Rrtype)
			matched := false
			for _, e := range existing {
				if rrEqualContent(e, rr) {
					matched = true
					break
				}
			}
			if !matched {
				status := ""
				if h.Rrtype == dns.TypeSOA {
					status = statusErrStaleSerial
				}
				return dns.RcodeNXRrset, status, fmt.Errorf(
					"rrset %s/%s does not currently match the required value (stale push?)", h.Name, dns.TypeToString[h.Rrtype])
			}
		default:
			return dns.RcodeFormatError, "", fmt.Errorf("malformed prerequisite for %s", h.Name)
		}
	}
	return dns.RcodeSuccess, "", nil
}

// ApplyUpdateOps applies RFC 2136 §2.5's four update forms to zone, in
// order, atomically -- see ZoneData.ApplyOps, which this just calls.
// Same reliance on wire-accurate Class/Rdlength as EvaluatePrerequisites.
// Callers are expected to have already evaluated prerequisites and
// authenticated the request -- this function performs no checks of its
// own beyond recognizing which of the four forms each op is.
func ApplyUpdateOps(zone *ZoneData, ops []dns.RR, zclass uint16) error {
	return zone.ApplyOps(ops, zclass)
}

// Prescan performs RFC 2136's syntax checks on an UPDATE's prerequisite
// (§3.2.1) and update (§3.4.1.3) sections before any of it is evaluated:
// every name must be in the zone (NOTZONE), and each RR's class, TTL and
// RDATA length must be one of the forms §2.4 and §2.5 define (FORMERR).
// Relies on wire-accurate Class/Rdlength, like EvaluatePrerequisites.
func Prescan(zone string, prereqs, updates []dns.RR, zclass uint16) (int, error) {
	for _, rr := range prereqs {
		h := rr.Header()
		if h.Ttl != 0 {
			return dns.RcodeFormatError, fmt.Errorf("prerequisite for %s has a nonzero TTL", h.Name)
		}
		if !dns.IsSubDomain(zone, h.Name) {
			return dns.RcodeNotZone, fmt.Errorf("prerequisite name %s is not in zone %s", h.Name, zone)
		}
		switch h.Class {
		case dns.ClassANY, dns.ClassNONE:
			if h.Rdlength != 0 {
				return dns.RcodeFormatError, fmt.Errorf("prerequisite for %s carries RDATA", h.Name)
			}
		case zclass:
		default:
			return dns.RcodeFormatError, fmt.Errorf("prerequisite for %s has class %d", h.Name, h.Class)
		}
	}
	for _, rr := range updates {
		h := rr.Header()
		if !dns.IsSubDomain(zone, h.Name) {
			return dns.RcodeNotZone, fmt.Errorf("update name %s is not in zone %s", h.Name, zone)
		}
		meta := h.Rrtype == dns.TypeAXFR || h.Rrtype == dns.TypeMAILA || h.Rrtype == dns.TypeMAILB
		switch h.Class {
		case zclass:
			if meta || h.Rrtype == dns.TypeANY {
				return dns.RcodeFormatError, fmt.Errorf("update adds a %s meta-type record at %s", dns.TypeToString[h.Rrtype], h.Name)
			}
		case dns.ClassANY:
			if h.Ttl != 0 || h.Rdlength != 0 || meta {
				return dns.RcodeFormatError, fmt.Errorf("malformed RRset delete at %s", h.Name)
			}
		case dns.ClassNONE:
			if h.Ttl != 0 || meta || h.Rrtype == dns.TypeANY {
				return dns.RcodeFormatError, fmt.Errorf("malformed RR delete at %s", h.Name)
			}
		default:
			return dns.RcodeFormatError, fmt.Errorf("update at %s has class %d", h.Name, h.Class)
		}
	}
	return dns.RcodeSuccess, nil
}
