package sazu

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DefaultMaxSIG0Lifetime is the longest SIG(0) validity window
// (expiration - inception) serveUpdate accepts: one hour plus five
// minutes of clock-skew allowance, per the protocol's replay-protection
// rules. sazuctl signs with inception one minute in the past and
// expiration one hour in the future, comfortably inside it. A tighter
// window bounds how long a captured message stays usable at all; the
// ReplayGuard below closes that window completely for anything this
// server has already accepted.
const DefaultMaxSIG0Lifetime = time.Hour + 5*time.Minute

// ReplayGuard enforces the protocol's per-key monotonic-inception rule:
// for every (zone, key) pair, the SIG(0) inception time of each accepted
// message must be strictly greater than that of the last message
// accepted from that key for that zone. A captured message -- replayed
// as-is, or held back and delivered after a newer one -- therefore never
// verifies twice, whatever it carries: an old content push can't roll
// the zone back, and a key-management message can't be re-applied (the
// motivating case: re-registering a ZSK that has since been retired).
//
// Marks are keyed by the full key (algorithm, key tag, public key), not
// the key tag alone, and are deliberately never removed -- not when a
// ZSK is retired, a KSK rolled over, or the whole zone decommissioned --
// so a message signed by a key the zone no longer trusts can't be
// replayed if that key ever becomes trusted again, or after the zone is
// re-onboarded. Growth is bounded by what gets accepted in the first
// place: a mark is only ever written for a message that passed SIG(0)
// verification and every other check, which the per-zone quotas already
// limit.
//
// A nil *ReplayGuard disables the check entirely -- only ever the case
// for a Sazu constructed directly (this package's own tests); setup.go
// always installs one.
type ReplayGuard struct {
	mu    sync.Mutex
	marks map[string]uint32
}

// NewReplayGuard returns an empty ReplayGuard.
func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{marks: make(map[string]uint32)}
}

// replayKeyID identifies key for ReplayGuard's purposes -- see
// ReplayGuard's doc comment for why this is the whole key, not just its
// tag.
func replayKeyID(key *dns.DNSKEY) string {
	return fmt.Sprintf("%d/%d/%s", key.Algorithm, key.KeyTag(), key.PublicKey)
}

func replayMapKey(zone, keyID string) string {
	return normalizeZone(zone) + "|" + keyID
}

// Allow reports whether a message for zone signed by key with the given
// SIG(0) inception is newer than anything already accepted from that key
// for that zone. It does not record anything -- call Record once the
// message has actually been applied, so a message rejected later for an
// unrelated reason doesn't burn its inception time.
func (g *ReplayGuard) Allow(zone string, key *dns.DNSKEY, inception uint32) bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	last, seen := g.marks[replayMapKey(zone, replayKeyID(key))]
	return !seen || inception > last
}

// Record notes inception as the newest accepted SIG(0) inception for
// (zone, key). It never moves a mark backwards.
func (g *ReplayGuard) Record(zone string, key *dns.DNSKEY, inception uint32) {
	if g == nil {
		return
	}
	g.set(replayMapKey(zone, replayKeyID(key)), inception)
}

func (g *ReplayGuard) set(k string, inception uint32) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if last, seen := g.marks[k]; !seen || inception > last {
		g.marks[k] = inception
	}
}

// ReplayMark is one persisted ReplayGuard entry -- see DB.CommitUpdateWithMark
// and DB.LoadReplayMarks.
type ReplayMark struct {
	Zone      string
	KeyID     string
	Inception uint32
}

// markFor builds the ReplayMark for a message from zone signed by key.
func markFor(zone string, key *dns.DNSKEY, inception uint32) *ReplayMark {
	return &ReplayMark{Zone: normalizeZone(zone), KeyID: replayKeyID(key), Inception: inception}
}

// Load seeds g from persisted marks, e.g. at startup.
func (g *ReplayGuard) Load(marks []ReplayMark) {
	for _, m := range marks {
		g.set(replayMapKey(m.Zone, m.KeyID), m.Inception)
	}
}

// serialGreater reports whether a is greater than b under RFC 1982
// serial number arithmetic (SERIAL_BITS = 32), the comparison RFC 1035
// SOA serials are defined to use.
func serialGreater(a, b uint32) bool {
	return a != b && a-b < 1<<31
}

// apexSOA returns the Add-shaped SOA at zone's apex among ops, if any.
func apexSOA(ops []dns.RR, zone string) *dns.SOA {
	for _, rr := range ops {
		soa, ok := rr.(*dns.SOA)
		if ok && soa.Hdr.Rdlength > 0 && strings.EqualFold(soa.Hdr.Name, dns.Fqdn(zone)) {
			return soa
		}
	}
	return nil
}
