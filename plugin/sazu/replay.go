package sazu

import (
	"crypto/sha256"
	"encoding/hex"
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

// ReplayGuard enforces the protocol's per-key replay rule. For every
// (zone, key) pair it remembers the newest SIG(0) inception accepted so
// far and a digest of each message accepted with exactly that
// inception. A message from that key for that zone is then accepted
// only if its inception is
//
//   - newer than the remembered one (the digest set starts over), or
//   - equal to it, and the message itself isn't one already accepted.
//
// So a captured message can never be applied twice, and one held back
// can never be applied after a newer second's message -- an old content
// push can't roll the zone back, and a key-management message can't be
// re-applied (the motivating case: re-registering a ZSK that has since
// been retired). Allowing equal inceptions keeps clients from having to
// wait: SIG(0) inception has one-second resolution, and requiring a
// strictly newer one would force every client to spend a second of its
// own on each signature (rotate-key alone signs twice). The cost is that
// two *different* messages signed by the same key within the same second
// aren't ordered against each other; the SOA serial rule (content) and
// the complete-DNSKEY-RRset rule (key management) still refuse anything
// that would move the zone backwards.
//
// Marks are keyed by the full key (algorithm, key tag, public key), not
// the key tag alone, and are deliberately never removed -- not when a
// ZSK is retired, a KSK rolled over, or the whole zone decommissioned --
// so a message signed by a key the zone no longer trusts can't be
// replayed if that key ever becomes trusted again, or after the zone is
// re-onboarded. Growth is bounded by what gets accepted in the first
// place: a mark is only ever written for a message that passed SIG(0)
// verification and every other check, which the per-zone quotas already
// limit, and only the newest second's digests are kept.
//
// A nil *ReplayGuard disables the check entirely -- only ever the case
// for a Sazu constructed directly (this package's own tests); setup.go
// always installs one.
type ReplayGuard struct {
	mu    sync.Mutex
	marks map[string]*replayState
}

type replayState struct {
	inception uint32
	seen      map[string]bool // digests of messages accepted at inception
}

// NewReplayGuard returns an empty ReplayGuard.
func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{marks: make(map[string]*replayState)}
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

// sig0Digest identifies one signed message: a hash of its SIG(0)
// signature, which covers the whole message and is unique to it.
func sig0Digest(sig *dns.SIG) string {
	sum := sha256.Sum256([]byte(sig.Signature))
	return hex.EncodeToString(sum[:])
}

// Allow reports whether a message for zone signed by key, with the given
// SIG(0) inception and digest (sig0Digest), may be accepted -- see
// ReplayGuard. It does not record anything: call Record once the
// message has actually been applied, so a message rejected later for an
// unrelated reason doesn't count as seen.
func (g *ReplayGuard) Allow(zone string, key *dns.DNSKEY, inception uint32, digest string) bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st, ok := g.marks[replayMapKey(zone, replayKeyID(key))]
	switch {
	case !ok || inception > st.inception:
		return true
	case inception == st.inception:
		return !st.seen[digest]
	default:
		return false
	}
}

// Record notes an accepted message for (zone, key).
func (g *ReplayGuard) Record(zone string, key *dns.DNSKEY, inception uint32, digest string) {
	if g == nil {
		return
	}
	g.merge(replayMapKey(zone, replayKeyID(key)), inception, []string{digest})
}

func (g *ReplayGuard) merge(k string, inception uint32, digests []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st, ok := g.marks[k]
	switch {
	case !ok || inception > st.inception:
		st = &replayState{inception: inception, seen: make(map[string]bool)}
		g.marks[k] = st
	case inception < st.inception:
		return
	}
	for _, d := range digests {
		st.seen[d] = true
	}
}

// ReplayMark is one persisted ReplayGuard entry -- see
// DB.CommitUpdateWithMark and DB.LoadReplayMarks. Digests are the
// messages accepted at exactly Inception.
type ReplayMark struct {
	Zone      string
	KeyID     string
	Inception uint32
	Digests   []string
}

// markFor builds the ReplayMark for one accepted message from zone
// signed by key.
func markFor(zone string, key *dns.DNSKEY, inception uint32, digest string) *ReplayMark {
	return &ReplayMark{Zone: normalizeZone(zone), KeyID: replayKeyID(key), Inception: inception, Digests: []string{digest}}
}

// Load seeds g from persisted marks, e.g. at startup.
func (g *ReplayGuard) Load(marks []ReplayMark) {
	for _, m := range marks {
		g.merge(replayMapKey(m.Zone, m.KeyID), m.Inception, m.Digests)
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
