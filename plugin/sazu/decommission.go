package sazu

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// decommissionOwnerPrefix names the reserved owner SAZU treats as a
// request to remove a zone entirely: a TXT RRset at
// "_sazu-decommission.<zone>", the same piggyback-on-an-ordinary-RRset-op
// convention contact.go already uses for the §10.6 registration-contact
// record. This is the one operation that removes a zone's KSK along with
// everything else -- there is otherwise no way to fully un-onboard a
// zone at all: every ordinary RFC 2136 delete-shaped op deliberately
// protects the apex SOA (see ZoneData.deleteRRsetLocked/deleteNameLocked),
// and nothing else in this package ever touches the KSK except a
// rollover, which replaces it rather than removing it.
const decommissionOwnerPrefix = "_sazu-decommission."

// decommissionMarkerValue is the fixed TXT content a decommission op
// carries. Its exact text is never inspected for meaning beyond "this op
// is present" -- unlike the contact record, there is no data to carry
// here, just a directive -- but a recognizable, non-empty value (rather
// than, say, an empty TXT) makes a decommission op unambiguous in a
// packet capture or audit log excerpt.
const decommissionMarkerValue = "decommission"

func decommissionOwnerName(zone string) string {
	return decommissionOwnerPrefix + normalizeZone(zone)
}

// BuildDecommissionOp builds the TXT record a client sends, as an
// ordinary Insert-shaped RFC 2136 Add op, to request zone's removal. Like
// BuildContactOp, this is deliberately NOT run through SignZoneContent: a
// decommission directive is not zone content and is never itself
// DNSSEC-signed -- SIG(0) on the containing UPDATE, required to be the
// KSK's (see splitDecommissionOps), already authenticates it.
func BuildDecommissionOp(zone string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: decommissionOwnerName(zone), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{decommissionMarkerValue},
	}
}

// splitDecommissionOps separates ops into the zone-content ops the rest
// of this package already knows how to handle and whether a decommission
// directive for zone is present. At most one is meaningful per push,
// and it may not be mixed with anything else -- content, a DNSKEY, a
// contact directive -- in the same transaction: decommissioning a zone is
// consequential enough (see handler.go's own gate requiring the KSK
// specifically) that a push meaning to do it should do nothing else,
// rather than leave room for "was the content also supposed to apply, or
// was that a mistake caught by decommissioning right after" ambiguity.
func splitDecommissionOps(ops []dns.RR, zone string) (rest []dns.RR, decommission bool, err error) {
	owner := decommissionOwnerName(zone)
	rest = make([]dns.RR, 0, len(ops))
	for _, rr := range ops {
		h := rr.Header()
		if strings.EqualFold(normalizeZone(h.Name), owner) && h.Rrtype == dns.TypeRRSIG {
			// Mirrors splitContactOps: drop a stray RRSIG a naive client
			// might have run this TXT through SignZoneContent to produce.
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeTXT {
				continue
			}
		}
		if !strings.EqualFold(normalizeZone(h.Name), owner) || h.Rrtype != dns.TypeTXT {
			rest = append(rest, rr)
			continue
		}
		if decommission {
			return nil, false, fmt.Errorf("more than one decommission directive in update")
		}
		if h.Class != dns.ClassINET || h.Rdlength == 0 {
			return nil, false, fmt.Errorf("malformed decommission directive")
		}
		decommission = true
	}
	if decommission && len(rest) > 0 {
		return nil, false, fmt.Errorf("a decommission directive may not be mixed with any other op in the same update")
	}
	return rest, decommission, nil
}
