package sazu

import (
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// ZoneData is one zone's live RRset store: name (lowercased FQDN) -> type
// -> RRs, plus its SOA tracked separately since queries for it are
// answered directly rather than via the generic map. Deliberately minimal
// -- SAZU needs "apply an accepted update and serve it back for testing
// the onboarding/full-push/partial-push flow end to end," not full
// authoritative fidelity (wildcards, delegation, NSEC). A production
// deployment would wire SAZU's acceptance logic into a real zone-storage
// backend instead of this self-contained one.
type ZoneData struct {
	Origin string

	mu     sync.RWMutex
	soa    *dns.SOA
	rrsets map[string]map[uint16][]dns.RR
}

// NewZoneData returns an empty zone for origin with no SOA yet -- callers
// creating a brand-new zone are expected to Insert one as part of the
// same update that creates it.
func NewZoneData(origin string) *ZoneData {
	return &ZoneData{Origin: dns.Fqdn(strings.ToLower(origin)), rrsets: make(map[string]map[uint16][]dns.RR)}
}

// SOA returns the zone's current SOA, or nil if none has been pushed yet.
func (z *ZoneData) SOA() *dns.SOA {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.soa
}

// Lookup returns a copy of the RRset for name/qtype, or nil if none.
func (z *ZoneData) Lookup(name string, qtype uint16) []dns.RR {
	z.mu.RLock()
	defer z.mu.RUnlock()
	name = strings.ToLower(name)
	if qtype == dns.TypeSOA && name == z.Origin {
		if z.soa == nil {
			return nil
		}
		return []dns.RR{dns.Copy(z.soa)}
	}
	byType, ok := z.rrsets[name]
	if !ok {
		return nil
	}
	out := make([]dns.RR, len(byType[qtype]))
	for i, rr := range byType[qtype] {
		out[i] = dns.Copy(rr)
	}
	return out
}

// LookupRRSIG returns the RRSIG(s) covering coveredType at name, if any.
// RRSIGs are stored like any other RR (under their own type, TypeRRSIG,
// in the same per-name map Lookup reads) -- including for the apex SOA,
// which is the one type Lookup itself special-cases into z.soa: a
// covering RRSIG is never diverted that way, since it isn't itself a
// *dns.SOA, so this needs no equivalent special case.
func (z *ZoneData) LookupRRSIG(name string, coveredType uint16) []dns.RR {
	z.mu.RLock()
	defer z.mu.RUnlock()
	name = strings.ToLower(name)
	byType, ok := z.rrsets[name]
	if !ok {
		return nil
	}
	var out []dns.RR
	for _, rr := range byType[dns.TypeRRSIG] {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == coveredType {
			out = append(out, dns.Copy(rr))
		}
	}
	return out
}

// NameExists reports whether name has any RRset at all (including being
// the zone apex, which always "exists" once a SOA has been pushed).
func (z *ZoneData) NameExists(name string) bool {
	z.mu.RLock()
	defer z.mu.RUnlock()
	name = strings.ToLower(name)
	if name == z.Origin && z.soa != nil {
		return true
	}
	byType, ok := z.rrsets[name]
	if !ok {
		return false
	}
	for _, rrs := range byType {
		if len(rrs) > 0 {
			return true
		}
	}
	return false
}

// Insert adds rr to its RRset, per RFC 2136 §3.4.2.2 ("Add To An
// RRset"): "In case of duplicate RDATAs ... the Zone RR is replaced by
// [the] Update RR" -- an RR identical in content (ignoring TTL) to one
// already in the RRset replaces it in place rather than accumulating a
// second, redundant copy. A SOA at the zone apex replaces the tracked
// SOA outright regardless of content (RFC 1035: a zone has exactly one
// SOA) rather than appending to a list of one.
func (z *ZoneData) Insert(rr dns.RR) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.insertLocked(rr)
}

func (z *ZoneData) insertLocked(rr dns.RR) {
	if soa, ok := rr.(*dns.SOA); ok && strings.EqualFold(rr.Header().Name, z.Origin) {
		z.soa = dns.Copy(soa).(*dns.SOA)
		return
	}
	name := strings.ToLower(rr.Header().Name)
	if z.rrsets[name] == nil {
		z.rrsets[name] = make(map[uint16][]dns.RR)
	}
	existing := z.rrsets[name][rr.Header().Rrtype]

	if sig, ok := rr.(*dns.RRSIG); ok {
		z.rrsets[name][rr.Header().Rrtype] = replaceRRSIG(existing, sig)
		return
	}

	if rr.Header().Rrtype == dns.TypeNSEC || rr.Header().Rrtype == dns.TypeNSEC3 || rr.Header().Rrtype == dns.TypeNSEC3PARAM {
		// Exactly one record of these types per name, always -- unlike
		// an ordinary RRset, a differing one at the same name (e.g. the
		// zone's name set changed and this name's "next" pointer needs
		// to reflect that, or a full push changed NSEC3's
		// iterations/salt) is a replacement, not a second value to keep
		// alongside the first. NSEC3PARAM only ever appears at the
		// apex, but is included here for the same reason: a changed
		// salt/iterations across two full pushes has different RDATA,
		// so RFC 2136's "identical RDATA replaces" rule alone wouldn't
		// catch it either.
		z.rrsets[name][rr.Header().Rrtype] = []dns.RR{dns.Copy(rr)}
		return
	}

	for i, e := range existing {
		if rrEqualContent(e, rr) {
			existing[i] = dns.Copy(rr) // replace -- refreshes TTL, per RFC 2136 §3.4.2.2
			return
		}
	}
	z.rrsets[name][rr.Header().Rrtype] = append(existing, dns.Copy(rr))
}

// replaceRRSIG adds sig to existing, first dropping any RRSIG already
// there that was produced by the same signer over the same covered type.
// RFC 2136 §3.4.2.2's "identical RDATA replaces" rule can't catch a
// re-signed RRset the way it catches an ordinary record: a fresh
// signature over unchanged content still has different RDATA (a new
// signature value, a new validity window), so by that rule alone it
// would just accumulate forever, once per re-sign, for as long as the
// zone exists -- eventually bloating every answer with expired
// signatures nothing ever removed. SAZU's single-key design (one signer
// per zone; no concurrent multi-key/algorithm rollover modeled by this
// in-memory store) means at most one active signature from a given
// signer should ever cover a given RRset at a time, so a fresh RRSIG
// from that signer replaces its own previous one instead of piling up
// beside it.
func replaceRRSIG(existing []dns.RR, sig *dns.RRSIG) []dns.RR {
	kept := existing[:0]
	for _, e := range existing {
		old, ok := e.(*dns.RRSIG)
		if ok && old.TypeCovered == sig.TypeCovered && old.Algorithm == sig.Algorithm &&
			old.KeyTag == sig.KeyTag && strings.EqualFold(old.SignerName, sig.SignerName) {
			continue
		}
		kept = append(kept, e)
	}
	return append(kept, dns.Copy(sig))
}

// DeleteRRset removes every RR of rtype at name (RFC 2136 §2.5.2).
func (z *ZoneData) DeleteRRset(name string, rtype uint16) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.deleteRRsetLocked(name, rtype)
}

func (z *ZoneData) deleteRRsetLocked(name string, rtype uint16) {
	name = strings.ToLower(name)
	if rtype == dns.TypeSOA && name == z.Origin {
		return // a zone's SOA is never removable this way, only replaced
	}
	if byType, ok := z.rrsets[name]; ok {
		delete(byType, rtype)
	}
}

// DeleteName removes every RRset at name, apex SOA excepted (RFC 2136
// §2.5.3 -- there is no protocol-level way to delete a zone this way,
// only its non-apex content).
func (z *ZoneData) DeleteName(name string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.deleteNameLocked(name)
}

func (z *ZoneData) deleteNameLocked(name string) {
	name = strings.ToLower(name)
	if name == z.Origin {
		return
	}
	delete(z.rrsets, name)
}

// DeleteRR removes one specific RR matching rr's content -- not its TTL,
// which RFC 2136 §2.5.4 deletes ignore -- from its RRset.
func (z *ZoneData) DeleteRR(rr dns.RR) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.deleteRRLocked(rr)
}

func (z *ZoneData) deleteRRLocked(rr dns.RR) {
	name := strings.ToLower(rr.Header().Name)
	byType, ok := z.rrsets[name]
	if !ok {
		return
	}
	rrs := byType[rr.Header().Rrtype]
	kept := rrs[:0]
	for _, existing := range rrs {
		if !rrEqualContent(existing, rr) {
			kept = append(kept, existing)
		}
	}
	byType[rr.Header().Rrtype] = kept
}

// PurgeContent removes every RRset in the zone except the apex DNSKEY
// RRset and its RRSIGs (key management is separate from content). A full
// content push replaces the zone, so this runs first; an RFC 2136 add
// alone never removes a record the new zone file no longer has. See
// PurgeContentAndApply, which does both under one lock so no query sees
// the zone in between.
func (z *ZoneData) PurgeContent() {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.purgeContentLocked()
}

func (z *ZoneData) purgeContentLocked() {
	for name, byType := range z.rrsets {
		isApex := name == z.Origin
		for rtype := range byType {
			if isApex && rtype == dns.TypeDNSKEY {
				continue
			}
			if isApex && rtype == dns.TypeRRSIG {
				kept := byType[rtype][:0]
				for _, rr := range byType[rtype] {
					if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeDNSKEY {
						kept = append(kept, rr)
					}
				}
				byType[rtype] = kept
				continue
			}
			delete(byType, rtype)
		}
		if len(byType) == 0 {
			delete(z.rrsets, name)
		}
	}
}

// applyOpLocked applies one RFC 2136 §2.5 update op, assuming the caller
// already holds z.mu -- the shared classification+dispatch ApplyUpdateOps
// and PurgeContentAndApply both use, so the two never risk disagreeing
// about which of the four forms a given op is.
func (z *ZoneData) applyOpLocked(rr dns.RR, zclass uint16) error {
	h := rr.Header()
	switch {
	case h.Class == zclass:
		z.insertLocked(rr)
	case h.Class == dns.ClassANY && h.Rrtype == dns.TypeANY && h.Rdlength == 0:
		z.deleteNameLocked(h.Name)
	case h.Class == dns.ClassANY && h.Rdlength == 0:
		z.deleteRRsetLocked(h.Name, h.Rrtype)
	case h.Class == dns.ClassNONE:
		z.deleteRRLocked(rr)
	default:
		return fmt.Errorf("malformed update op for %s", h.Name)
	}
	return nil
}

// ApplyOps applies every op in ops (RFC 2136 §2.5's four update forms),
// all under one lock acquisition -- atomically, from the perspective of
// any concurrent query, the same reasoning PurgeContentAndApply's own
// doc comment explains in more detail. ApplyUpdateOps (prereq.go) is a
// thin wrapper around this; the two names exist because most callers
// think in terms of "apply this update," not "this zone's own method."
func (z *ZoneData) ApplyOps(ops []dns.RR, zclass uint16) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.dropSupersededDNSKEYSigsLocked(ops, zclass)
	for _, rr := range ops {
		if err := z.applyOpLocked(rr, zclass); err != nil {
			return err
		}
	}
	return nil
}

// PurgeContentAndApply performs PurgeContent and then applies every op
// in ops, all under one lock acquisition -- atomically, from the
// perspective of any concurrent query (serveQuery's Lookup/NameExists
// calls each take z.mu independently). Without this, a full content
// push that purges first and then re-inserts one record at a time (each
// insert its own separate lock/unlock) would leave a real window where
// a concurrent query sees a record as gone that both existed a moment
// before the push and will exist again a moment after it -- even though
// nothing about that record actually changed. Used for the containsAPEXSOA
// case in handler.go's serveUpdate; ApplyUpdateOps (used everywhere else)
// makes the same atomicity guarantee for its own multi-op sequence, just
// without the purge first.
func (z *ZoneData) PurgeContentAndApply(ops []dns.RR, zclass uint16) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.purgeContentLocked()
	z.dropSupersededDNSKEYSigsLocked(ops, zclass)
	for _, rr := range ops {
		if err := z.applyOpLocked(rr, zclass); err != nil {
			return err
		}
	}
	return nil
}

// rrEqualContent compares two RRs by name/type/rdata only, ignoring TTL
// and Class. TTL is never part of RFC 2136 delete matching. Class also
// has to be ignored here specifically because RFC 2136 §2.5.4 "delete an
// RR" (and this store's own DeleteRR caller) carries the real rdata
// alongside Class NONE as a wire-protocol marker for "this is a delete,"
// not as part of the record's identity -- the stored record being
// deleted has the zone's real class (usually IN), so comparing Class
// along with the rest would make every such delete a no-op.
func rrEqualContent(a, b dns.RR) bool {
	a2, b2 := dns.Copy(a), dns.Copy(b)
	a2.Header().Ttl, b2.Header().Ttl = 0, 0
	a2.Header().Class, b2.Header().Class = 0, 0
	return a2.String() == b2.String()
}

// Store holds every zone this plugin instance is currently serving,
// keyed by origin.
type Store struct {
	mu    sync.RWMutex
	zones map[string]*ZoneData
}

// NewStore returns an empty Store.
func NewStore() *Store {
	return &Store{zones: make(map[string]*ZoneData)}
}

// Get returns the zone for origin, if it has been created (by a
// successful first-contact push).
func (s *Store) Get(origin string) (*ZoneData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	z, ok := s.zones[dns.Fqdn(strings.ToLower(origin))]
	return z, ok
}

// GetOrCreate returns the existing zone for origin, or creates and
// registers a new empty one.
func (s *Store) GetOrCreate(origin string) *ZoneData {
	origin = dns.Fqdn(strings.ToLower(origin))
	s.mu.Lock()
	defer s.mu.Unlock()
	if z, ok := s.zones[origin]; ok {
		return z
	}
	z := NewZoneData(origin)
	s.zones[origin] = z
	return z
}

// DeleteZone removes origin entirely -- every RRset, the SOA, all of
// it -- so a subsequent Get/FindZoneForName sees no trace of it, the same
// as a zone this Store has never heard of. Called only for a decommission
// directive (decommission.go); nothing else in this package ever fully
// removes a zone (an ordinary RFC 2136 delete-shaped op always protects
// the apex SOA, deliberately -- see deleteRRsetLocked/deleteNameLocked).
func (s *Store) DeleteZone(origin string) {
	origin = dns.Fqdn(strings.ToLower(origin))
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.zones, origin)
}

// FindZoneForName returns the most specific onboarded zone name falls
// under, if any -- a longest-suffix match over every zone this Store
// currently holds, independent of any static configuration. This is what
// lets many customer domains be onboarded dynamically under one broad
// plugin scope (e.g. a Corefile's "sazu ."), with no per-domain Corefile
// edit needed: the set of zones this searches is whatever has actually
// been onboarded, not a fixed list. A zone counts as found once it has
// either a SOA or an apex DNSKEY RRset: a zone onboarded by a keys-only
// first contact (sazuctl publish-trust) has no content, and so no SOA,
// until its first publish-zone push, but must still answer DNSKEY
// queries in between -- add-zsk, retire-zsk and rotate-key read the live
// DNSKEY RRset before signing a change to it. A zone with neither (an
// empty placeholder left by a rejected update) doesn't count.
func (s *Store) FindZoneForName(name string) (origin string, zone *ZoneData, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best string
	var bestZone *ZoneData
	for candidate, z := range s.zones {
		if z.SOA() == nil && len(z.Lookup(candidate, dns.TypeDNSKEY)) == 0 {
			continue
		}
		if dns.IsSubDomain(candidate, name) && len(candidate) > len(best) {
			best, bestZone = candidate, z
		}
	}
	if bestZone == nil {
		return "", nil, false
	}
	return best, bestZone, true
}

// addsApexDNSKEYSig reports whether ops adds an RRSIG over origin's
// DNSKEY RRset.
func addsApexDNSKEYSig(ops []dns.RR, origin string, zclass uint16) bool {
	for _, rr := range ops {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.Hdr.Class == zclass && sig.TypeCovered == dns.TypeDNSKEY &&
			strings.EqualFold(sig.Hdr.Name, origin) {
			return true
		}
	}
	return false
}

// dropSupersededDNSKEYSigsLocked removes every stored RRSIG over the apex
// DNSKEY RRset when ops brings new ones. An update that changes the
// DNSKEY RRset always carries it complete, freshly signed by the KSK
// (serveUpdate enforces both), so every earlier signature over it --
// including one by a KSK that just left the set in a rollover, which
// replaceRRSIG's same-signer rule would never catch -- is stale.
// Callers must hold z.mu.
func (z *ZoneData) dropSupersededDNSKEYSigsLocked(ops []dns.RR, zclass uint16) {
	if !addsApexDNSKEYSig(ops, z.Origin, zclass) {
		return
	}
	byType, ok := z.rrsets[strings.ToLower(z.Origin)]
	if !ok {
		return
	}
	kept := byType[dns.TypeRRSIG][:0]
	for _, rr := range byType[dns.TypeRRSIG] {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeDNSKEY {
			continue
		}
		kept = append(kept, rr)
	}
	byType[dns.TypeRRSIG] = kept
}
