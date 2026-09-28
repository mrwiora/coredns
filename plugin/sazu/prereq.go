package sazu

import (
	"fmt"

	"github.com/coredns/coredns/plugin/pkg/rfc2136"

	"github.com/miekg/dns"
)

// EvaluatePrerequisites evaluates RFC 2136 §2.4 prerequisites against
// zone's current content (rfc2136.CheckPrerequisites). It returns the
// RCODE of the first failure, ERR_STALE_SERIAL when that was the SOA
// prerequisite (the staleness guard of BuildFullZonePush's previousSOA),
// and a description; or (dns.RcodeSuccess, "", nil). The forms are told
// apart by Class and Rdlength as unpacked from the wire.
func EvaluatePrerequisites(zone *ZoneData, prereqs []dns.RR, zclass uint16) (int, string, error) {
	rcode, failed := rfc2136.CheckPrerequisites(zone.Origin, prereqs, zclass, zone, nil)
	if rcode == dns.RcodeSuccess {
		return rcode, "", nil
	}
	status := ""
	if failed != nil && failed.Header().Rrtype == dns.TypeSOA && failed.Header().Class == zclass {
		status = statusErrStaleSerial
	}
	return rcode, status, fmt.Errorf("prerequisite %v failed: %s", failed, dns.RcodeToString[rcode])
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

// Prescan performs RFC 2136's checks on the form of an UPDATE's
// prerequisite (§3.2.1) and update (§3.4.1.3) sections before any of it is
// evaluated (NOTZONE, FORMERR).
func Prescan(zone string, prereqs, updates []dns.RR, zclass uint16) (int, error) {
	if rcode, rr := rfc2136.PrescanPrerequisites(zone, prereqs, zclass, nil); rcode != dns.RcodeSuccess {
		return rcode, fmt.Errorf("prerequisite %v: %s", rr, dns.RcodeToString[rcode])
	}
	if rcode, rr := rfc2136.PrescanUpdates(zone, updates, zclass, nil); rcode != dns.RcodeSuccess {
		return rcode, fmt.Errorf("update %v: %s", rr, dns.RcodeToString[rcode])
	}
	return dns.RcodeSuccess, nil
}
