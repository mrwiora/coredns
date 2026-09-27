package sazu

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/coredns/coredns/plugin"

	"github.com/miekg/dns"
)

// Replay protection rests on two per-zone counters that are part of the
// zone's own state -- nothing depends on clocks, and nothing about it
// lives outside what a replica of the zone would have to carry anyway:
//
//   - Content: a full push must raise the SOA serial (RFC 1982), so an
//     older push -- replayed, or held back and delivered late -- can
//     never be applied over a newer one.
//   - Control: every change to a zone's control state (onboarding, a
//     change to its DNSKEY RRset, a KSK rollover, a contact change,
//     decommission) must name the zone's current *version* in an RFC
//     2136 value-dependent prerequisite, and each accepted one increments
//     it. A captured control message is valid for exactly one version:
//     once applied -- or once anything else has changed the control
//     state -- it can never apply again, in any order, on any server
//     that holds the zone's current version.
//
// Content pushes deliberately don't touch the version: a key-management
// message prepared on an offline KSK host stays valid across any number
// of routine ZSK content pushes in the meantime. The one content push
// that does need it is a zone's first (no SOA served yet, so there is
// no serial to compare against).
//
// The version is published, unsigned, as a TXT record at
// "_sazu-version.<zone>" so a client can read it before signing, and is
// kept after a zone is decommissioned (and incremented by it), so an old
// onboarding message can't re-create a deleted zone either.
const versionOwnerPrefix = "_sazu-version."

// VersionOwnerName returns the reserved owner name zone's version is
// published and required at.
func VersionOwnerName(zone string) string {
	return versionOwnerPrefix + normalizeZone(zone)
}

// BuildVersionPrereq builds the RFC 2136 §2.4.2 "RRset exists (value
// dependent)" prerequisite asserting that zone's version is v. A client
// adds it to an UPDATE's prerequisite section (dns.Msg.Answer) before
// signing.
func BuildVersionPrereq(zone string, v uint64) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: VersionOwnerName(zone), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: []string{strconv.FormatUint(v, 10)},
	}
}

// splitVersionPrereq separates zone's version prerequisite, if any, from
// the rest of prereqs. More than one, or one of any other shape at the
// reserved name, is an error.
func splitVersionPrereq(prereqs []dns.RR, zone string) (rest []dns.RR, version uint64, present bool, err error) {
	owner := VersionOwnerName(zone)
	rest = make([]dns.RR, 0, len(prereqs))
	for _, rr := range prereqs {
		h := rr.Header()
		if !strings.EqualFold(h.Name, owner) {
			rest = append(rest, rr)
			continue
		}
		txt, ok := rr.(*dns.TXT)
		if !ok || h.Class != dns.ClassINET || len(txt.Txt) != 1 {
			return nil, 0, false, fmt.Errorf("malformed version prerequisite at %s", owner)
		}
		if present {
			return nil, 0, false, fmt.Errorf("more than one version prerequisite at %s", owner)
		}
		version, err = strconv.ParseUint(txt.Txt[0], 10, 64)
		if err != nil {
			return nil, 0, false, fmt.Errorf("version prerequisite at %s: %w", owner, err)
		}
		present = true
	}
	return rest, version, present, nil
}

// touchesReservedName reports whether updateOps adds or deletes anything
// at zone's version owner name -- which only the server itself ever
// writes.
func touchesReservedName(updateOps []dns.RR, zone string) bool {
	owner := VersionOwnerName(zone)
	for _, rr := range updateOps {
		if strings.EqualFold(rr.Header().Name, owner) {
			return true
		}
	}
	return false
}

// VersionRegistry holds every zone's current control-state version,
// including zones that were decommissioned (see versionOwnerPrefix). A
// zone never seen has version 0.
type VersionRegistry struct {
	mu       sync.RWMutex
	versions map[string]uint64
}

// NewVersionRegistry returns an empty VersionRegistry.
func NewVersionRegistry() *VersionRegistry {
	return &VersionRegistry{versions: make(map[string]uint64)}
}

// Get returns zone's current version.
func (r *VersionRegistry) Get(zone string) uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.versions[normalizeZone(zone)]
}

// Set records v as zone's current version.
func (r *VersionRegistry) Set(zone string, v uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.versions[normalizeZone(zone)] = v
}

// versionAnswer answers a TXT (or ANY) query for a zone's version owner
// name, if qname is one and the zone is within scope; ok is false
// otherwise.
func (s *Sazu) versionAnswer(r *dns.Msg) (m *dns.Msg, ok bool) {
	q := r.Question[0]
	name := strings.ToLower(dns.Fqdn(q.Name))
	if !strings.HasPrefix(name, versionOwnerPrefix) || (q.Qtype != dns.TypeTXT && q.Qtype != dns.TypeANY) {
		return nil, false
	}
	zone := strings.TrimPrefix(name, versionOwnerPrefix)
	if zone == "" || plugin.Zones(s.Zones).Matches(zone) == "" {
		return nil, false
	}
	m = new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	txt := BuildVersionPrereq(zone, s.Versions.Get(zone))
	txt.Hdr.Name = q.Name
	m.Answer = []dns.RR{txt}
	return m, true
}
