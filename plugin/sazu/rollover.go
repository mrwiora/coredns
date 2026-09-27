package sazu

import (
	"crypto"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// KSK rollover hold-down.
//
// A KSK rollover is authenticated by the *new* KSK plus a DS for it at
// the parent -- deliberately, so a zone owner who lost the old KSK can
// still recover as long as they control the registrar. On its own, that
// would let anyone who compromises the registrar take the zone over at
// this server instantly. So:
//
//   - a rollover whose new DNSKEY RRset is also signed by the currently
//     pinned (old) KSK -- proof the current key holder consents -- applies
//     immediately. That co-signature is verified and then dropped; it is
//     never stored or served, since the old KSK leaves the RRset;
//   - a rollover proven only by the new key and its DS is recorded as
//     *pending* on its first attempt (ERR_ROLLOVER_PENDING, with the
//     earliest completion time), and sazu-watchd alerts the zone's
//     contact. It completes only when the same rollover is sent again
//     after the hold-down, with the DS still published;
//   - any control change the pinned KSK authenticates in the meantime --
//     including the explicit cancel directive below -- cancels it.
//
// So a registrar compromise can't take over a zone whose owner still
// holds the KSK: the owner is alerted and has the whole hold-down to
// cancel.

// DefaultRolloverHoldDown is the hold-down setup.go applies unless the
// Corefile's rollover_hold_down says otherwise.
const DefaultRolloverHoldDown = 72 * time.Hour

// PendingRollover is a DS-only KSK rollover waiting out its hold-down.
type PendingRollover struct {
	KSK         *dns.DNSKEY
	RequestedAt time.Time
}

// PendingRollovers holds the pending rollover, if any, per zone. A nil
// *PendingRollovers holds nothing (only this package's tests leave it
// unset, with no hold-down configured).
type PendingRollovers struct {
	mu      sync.Mutex
	pending map[string]PendingRollover
}

// NewPendingRollovers returns an empty PendingRollovers.
func NewPendingRollovers() *PendingRollovers {
	return &PendingRollovers{pending: make(map[string]PendingRollover)}
}

// Get returns zone's pending rollover, if any.
func (p *PendingRollovers) Get(zone string) (PendingRollover, bool) {
	if p == nil {
		return PendingRollover{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	pr, ok := p.pending[normalizeZone(zone)]
	return pr, ok
}

// Set records pr as zone's pending rollover, replacing any other.
func (p *PendingRollovers) Set(zone string, pr PendingRollover) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending[normalizeZone(zone)] = pr
}

// Clear removes zone's pending rollover, if any.
func (p *PendingRollovers) Clear(zone string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pending, normalizeZone(zone))
}

// stripKSKCoSignature removes from ops every RRSIG over zone's apex
// DNSKEY RRset made by oldKSK, reporting whether one of them verifies
// over the DNSKEY RRset the update adds -- the old KSK's consent to a
// rollover. Invalid ones are dropped too (they'd be refused anyway as an
// RRSIG from a key not allowed to sign the RRset, and there's nothing
// to gain from telling the two failures apart).
func stripKSKCoSignature(ops []dns.RR, zone string, oldKSK *dns.DNSKEY) (rest []dns.RR, coSigned bool) {
	var keys []dns.RR
	for _, k := range addedDNSKEYs(ops, zone) {
		keys = append(keys, k)
	}
	rest = make([]dns.RR, 0, len(ops))
	for _, rr := range ops {
		sig, ok := rr.(*dns.RRSIG)
		if ok && sig.TypeCovered == dns.TypeDNSKEY && strings.EqualFold(sig.Hdr.Name, dns.Fqdn(zone)) &&
			sig.KeyTag == oldKSK.KeyTag() && sig.Algorithm == oldKSK.Algorithm {
			if len(keys) > 0 && sig.Verify(oldKSK, keys) == nil && sig.ValidityPeriod(time.Now()) {
				coSigned = true
			}
			continue
		}
		rest = append(rest, rr)
	}
	return rest, coSigned
}

// cancelRolloverPrefix names the reserved owner of the explicit
// cancel-a-pending-rollover directive -- the same piggyback-on-a-TXT-op
// convention contact.go and decommission.go use.
const cancelRolloverPrefix = "_sazu-cancel-rollover."

func cancelRolloverOwnerName(zone string) string {
	return cancelRolloverPrefix + normalizeZone(zone)
}

// splitCancelRolloverOps separates the cancel directive, if present,
// from ops.
func splitCancelRolloverOps(ops []dns.RR, zone string) (rest []dns.RR, cancel bool, err error) {
	owner := cancelRolloverOwnerName(zone)
	rest = make([]dns.RR, 0, len(ops))
	for _, rr := range ops {
		h := rr.Header()
		if !strings.EqualFold(h.Name, owner) {
			rest = append(rest, rr)
			continue
		}
		if _, ok := rr.(*dns.TXT); !ok || h.Class != dns.ClassINET || cancel {
			return nil, false, fmt.Errorf("malformed cancel-rollover directive at %s", owner)
		}
		cancel = true
	}
	return rest, cancel, nil
}

// BuildCancelRolloverPush builds an UPDATE cancelling zone's pending
// KSK rollover. It must be SIG(0)-signed by the pinned KSK and carry the
// zone's version prerequisite, like any control change.
func BuildCancelRolloverPush(zone string) *dns.Msg {
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))
	m.Insert([]dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: cancelRolloverOwnerName(zone), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: []string{"cancel-rollover"},
	}})
	return m
}

// BuildKSKRolloverPushCoSigned is BuildKSKRolloverPush plus the old
// KSK's co-signature over the new DNSKEY RRset, which lets the rollover
// apply immediately instead of waiting out the hold-down. The server
// verifies the co-signature and drops it.
func BuildKSKRolloverPushCoSigned(zone string, current []*dns.DNSKEY, oldKSK *dns.DNSKEY, oldPriv crypto.Signer, newKSK *dns.DNSKEY, newPriv crypto.Signer) (*dns.Msg, error) {
	m, err := BuildKSKRolloverPush(zone, current, oldKSK, newKSK, newPriv)
	if err != nil {
		return nil, err
	}
	// m was built in Go, not unpacked, so pick the adds by class (an add
	// carries IN; RFC 2136 deletes carry ANY or NONE) rather than by
	// Rdlength the way addedDNSKEYs does for received messages.
	var keys []dns.RR
	for _, rr := range m.Ns {
		if k, ok := rr.(*dns.DNSKEY); ok && k.Hdr.Class == dns.ClassINET {
			keys = append(keys, k)
		}
	}
	now := time.Now()
	sig, err := signOneRRset(keys, oldKSK, oldPriv, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
	if err != nil {
		return nil, err
	}
	m.Insert([]dns.RR{sig})
	return m, nil
}
