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
// one (the SOA-serial staleness guard's ERR_STALE_SERIAL, or the
// NSEC/NSEC3 chain-patch staleness guard's ERR_STALE_CHAIN; "" for every
// other, more generic RFC 2136 prerequisite failure), the zone's actual
// current RRset for a value-dependent (§2.4.2) mismatch specifically --
// nil for every other failure kind, where "what's actually there" isn't
// a single well-defined RRset the way a stale value-dependent assertion's
// is -- and a human-readable reason. Or (dns.RcodeSuccess, "", nil, nil)
// if every prerequisite holds.
//
// current exists so a caller can hand the real, current value back to
// the client that asserted a stale one -- see handler.go's serveUpdate,
// which does exactly this for a stale chain-patch prerequisite (the
// "fetch what's actually there" half of that mechanism): a §2.4.2
// mismatch is always unambiguous (this function fails on the very first
// unsatisfied prerequisite, so there is exactly one RRset in question),
// unlike a zone-wide diff, which would need to guess at what a client
// might find useful.
func EvaluatePrerequisites(zone *ZoneData, prereqs []dns.RR, zclass uint16) (rcode int, status string, current []dns.RR, err error) {
	for _, rr := range prereqs {
		h := rr.Header()
		switch {
		case h.Class == dns.ClassANY && h.Rrtype == dns.TypeANY && h.Rdlength == 0:
			// §2.4.4 Name is in use.
			if !zone.NameExists(h.Name) {
				return dns.RcodeNameError, "", nil, fmt.Errorf("name %s is not in use", h.Name)
			}
		case h.Class == dns.ClassNONE && h.Rrtype == dns.TypeANY && h.Rdlength == 0:
			// §2.4.5 Name is not in use.
			if zone.NameExists(h.Name) {
				return dns.RcodeYXDomain, "", nil, fmt.Errorf("name %s is already in use", h.Name)
			}
		case h.Class == dns.ClassANY && h.Rdlength == 0:
			// §2.4.1 RRset exists (value-independent).
			if len(zone.Lookup(h.Name, h.Rrtype)) == 0 {
				return dns.RcodeNXRrset, "", nil, fmt.Errorf("rrset %s/%s does not exist", h.Name, dns.TypeToString[h.Rrtype])
			}
		case h.Class == dns.ClassNONE && h.Rdlength == 0:
			// §2.4.3 RRset does not exist.
			if len(zone.Lookup(h.Name, h.Rrtype)) != 0 {
				return dns.RcodeYXRrset, "", nil, fmt.Errorf("rrset %s/%s exists but must not", h.Name, dns.TypeToString[h.Rrtype])
			}
		case h.Class == zclass:
			// §2.4.2 RRset exists (value-dependent) -- the SOA-serial
			// staleness guard (BuildFullZonePush's previousSOA parameter)
			// and the NSEC/NSEC3 chain-patch staleness guard (a partial
			// push's own asserted "the record at this neighbor owner
			// name is still exactly this") both use this form, which is
			// what lets this branch tell those specific, common cases
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
				switch h.Rrtype {
				case dns.TypeSOA:
					status = statusErrStaleSerial
				case dns.TypeNSEC, dns.TypeNSEC3:
					status = statusErrStaleChain
				}
				return dns.RcodeNXRrset, status, existing, fmt.Errorf(
					"rrset %s/%s does not currently match the required value (stale push?)", h.Name, dns.TypeToString[h.Rrtype])
			}
		default:
			return dns.RcodeFormatError, "", nil, fmt.Errorf("malformed prerequisite for %s", h.Name)
		}
	}
	return dns.RcodeSuccess, "", nil, nil
}

// ApplyUpdateOps applies RFC 2136 §2.5's four update forms to zone, in
// order. Same reliance on wire-accurate Class/Rdlength as
// EvaluatePrerequisites. Callers are expected to have already evaluated
// prerequisites and authenticated the request -- this function performs
// no checks of its own beyond recognizing which of the four forms each
// op is.
func ApplyUpdateOps(zone *ZoneData, ops []dns.RR, zclass uint16) error {
	for _, rr := range ops {
		h := rr.Header()
		switch {
		case h.Class == zclass:
			// §2.5.1 Add to an RRset.
			zone.Insert(rr)
		case h.Class == dns.ClassANY && h.Rrtype == dns.TypeANY && h.Rdlength == 0:
			// §2.5.3 Delete all RRsets from a name.
			zone.DeleteName(h.Name)
		case h.Class == dns.ClassANY && h.Rdlength == 0:
			// §2.5.2 Delete an RRset.
			zone.DeleteRRset(h.Name, h.Rrtype)
		case h.Class == dns.ClassNONE:
			// §2.5.4 Delete an RR from an RRset.
			zone.DeleteRR(rr)
		default:
			return fmt.Errorf("malformed update op for %s", h.Name)
		}
	}
	return nil
}
