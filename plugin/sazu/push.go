package sazu

import (
	"crypto"
	"fmt"
	"os"
	"time"

	"github.com/miekg/dns"
)

// Default RRSIG validity window for content this package signs.
// Independent of, and much longer than, a SIG(0) transaction signature's
// own inception/expiration (typically ~1 hour, protecting the UPDATE
// message itself against replay): this window protects the *zone
// content* — how long it stays validly signed once served, which is
// what a customer's re-signing schedule needs to stay ahead of.
const (
	DefaultSignatureInceptionSkew = 1 * time.Hour
	DefaultSignatureValidity      = 30 * 24 * time.Hour
)

// LoadZoneFile parses a BIND-format zone file and returns its SOA record
// and every other RR it contains. A full-zone SAZU push (§12) sends the
// customer's own zone content exactly as they maintain it -- not a
// synthetic subset built record by record, the way the earlier sazuctl
// push command demonstrated the protocol with a single A record.
func LoadZoneFile(path, origin string) (soa *dns.SOA, rrs []dns.RR, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	zp := dns.NewZoneParser(f, dns.Fqdn(origin), path)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if s, isSOA := rr.(*dns.SOA); isSOA {
			if soa != nil {
				return nil, nil, fmt.Errorf("%s: more than one SOA record", path)
			}
			soa = s
			continue
		}
		rrs = append(rrs, rr)
	}
	if err := zp.Err(); err != nil {
		return nil, nil, err
	}
	if soa == nil {
		return nil, nil, fmt.Errorf("%s: no SOA record found", path)
	}
	return soa, rrs, nil
}

// BuildFullZonePush builds an RFC 2136 UPDATE message for a full-zone
// SAZU push (§12): the candidate DNSKEY plus every record in the zone
// (soa included, so the pushed SOA actually becomes part of what the
// server serves -- it is content, not just a version marker).
//
// previousSOA, if non-nil, adds an RFC 2136 §2.4.2 "RRset exists, value
// dependent" prerequisite against it -- the SOA-serial staleness guard:
// the update only applies if previousSOA is still the server's current
// SOA, so a push built from a zone snapshot the server has already moved
// past gets rejected rather than silently regressing it. Pass nil for a
// first-contact push: there is no previously-published SOA yet to be
// stale against, and §10.2 explicitly carries no prerequisites of its
// own at first contact.
//
// candidateKey is added as a DNSKEY at the zone apex -- the design's
// central decision (§9.1: the same key signs and authenticates), so it
// always travels with the push, first contact or not.
//
// signer is that same key's private half, used to actually sign the
// pushed content (DNSKEY, SOA, every RRset in rrs, and a freshly
// computed NSEC chain covering all of it -- see BuildNSECChain) with
// real RFC 4034 RRSIGs via SignZoneContent -- this is what SAZU's whole
// premise ("split-signing DNSSEC," the hoster never touches a private
// key) actually requires: SIG(0) alone only authenticates the push
// *transaction*, not the zone *content*. Without this, a validating
// resolver would see a zone with a published DS but no RRSIGs at all —
// exactly the "bogus" state that produces SERVFAIL for real DNSSEC
// clients, regardless of whether the push mechanics themselves are sound.
//
// A full push is the only kind that ever computes or sends a
// denial-of-existence chain -- it's the only one that sees the zone's
// entire name set at once, which a correct chain needs. The server
// invalidates any existing chain before applying a push that doesn't
// include one (see ZoneData.PurgeNSEC); this one always does.
func BuildFullZonePush(zone string, soa *dns.SOA, rrs []dns.RR, candidateKey *dns.DNSKEY, signer crypto.Signer, previousSOA *dns.SOA) (*dns.Msg, error) {
	return BuildFullZonePushSplit(zone, soa, rrs, candidateKey, signer, nil, nil, previousSOA)
}

// BuildFullZonePushSplit is BuildFullZonePush's optional-ZSK
// generalization: ksk is always added as a DNSKEY at the apex and always
// signs the DNSKEY RRset (RFC 4034's own convention -- the key-signing
// key signs the key set). If zsk is non-nil, it is *also* added as a
// DNSKEY at the apex (so the DNSKEY RRset this push asserts reflects the
// zone's whole current key state, not just its KSK) and signs every
// *other* RRset -- the zone's actual content -- instead of ksk. Passing
// zsk as nil reproduces BuildFullZonePush's original single-key behavior
// exactly (byte-for-byte: it's the same code path with the same key
// signing everything), which is what BuildFullZonePush itself now does.
//
// Uses plain NSEC (BuildNSECChain). See BuildFullZonePushSplitNSEC3 for
// the RFC 5155 NSEC3 alternative.
func BuildFullZonePushSplit(zone string, soa *dns.SOA, rrs []dns.RR, ksk *dns.DNSKEY, kskSigner crypto.Signer, zsk *dns.DNSKEY, zskSigner crypto.Signer, previousSOA *dns.SOA) (*dns.Msg, error) {
	return buildFullZonePushSplit(zone, soa, rrs, ksk, kskSigner, zsk, zskSigner, previousSOA, BuildNSECChain)
}

// BuildFullZonePushNSEC3 is BuildFullZonePush's RFC 5155 NSEC3
// equivalent -- see BuildNSEC3Chain and NSEC3Options.
func BuildFullZonePushNSEC3(zone string, soa *dns.SOA, rrs []dns.RR, candidateKey *dns.DNSKEY, signer crypto.Signer, previousSOA *dns.SOA, opts NSEC3Options) (*dns.Msg, error) {
	return BuildFullZonePushSplitNSEC3(zone, soa, rrs, candidateKey, signer, nil, nil, previousSOA, opts)
}

// BuildFullZonePushSplitNSEC3 is BuildFullZonePushSplit's RFC 5155
// NSEC3 equivalent -- see BuildNSEC3Chain and NSEC3Options. Choosing
// NSEC3 over plain NSEC is a push-time decision the customer's own
// signer makes (there is no server-side toggle: the server just stores
// and serves whichever chain it was given), so this is a distinct entry
// point rather than an option on BuildFullZonePushSplit.
func BuildFullZonePushSplitNSEC3(zone string, soa *dns.SOA, rrs []dns.RR, ksk *dns.DNSKEY, kskSigner crypto.Signer, zsk *dns.DNSKEY, zskSigner crypto.Signer, previousSOA *dns.SOA, opts NSEC3Options) (*dns.Msg, error) {
	return buildFullZonePushSplit(zone, soa, rrs, ksk, kskSigner, zsk, zskSigner, previousSOA, func(soa *dns.SOA, adds []dns.RR) []dns.RR {
		return BuildNSEC3Chain(soa, adds, opts)
	})
}

// BuildTrustPush builds an RFC 2136 UPDATE message that establishes a
// zone's KSK/ZSK trust relationship without touching any zone content at
// all: the apex DNSKEY RRset, containing both ksk and zsk, signed by ksk
// alone (RFC 4034's own convention -- the key-signing key signs the key
// set; zsk's own private half is never needed here). This is sazuctl
// publish-trust's whole job: generate the pair together, present them,
// and never need the KSK again for anything but a future rollover -- see
// BuildContentPush for the ZSK-only, DNSKEY-free routine push that
// follows it.
//
// The transaction itself (SIG(0), via SignUpdate) must also be signed by
// ksk -- first contact only ever trusts the SEP-flagged (KSK-shaped) key
// among a push's candidates to authenticate it (see handler.go's
// findCandidateKey).
func BuildTrustPush(zone string, ksk *dns.DNSKEY, kskSigner crypto.Signer, zsk *dns.DNSKEY) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	m.Opcode = dns.OpcodeUpdate

	kskRR := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     ksk.Flags, Protocol: ksk.Protocol, Algorithm: ksk.Algorithm, PublicKey: ksk.PublicKey,
	}
	zskRR := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     zsk.Flags, Protocol: zsk.Protocol, Algorithm: zsk.Algorithm, PublicKey: zsk.PublicKey,
	}

	now := time.Now()
	signed, err := SignZoneContentSplit([]dns.RR{kskRR, zskRR}, kskRR, kskSigner, kskRR, kskSigner,
		now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
	if err != nil {
		return nil, err
	}
	m.Insert(signed)
	return m, nil
}

// dnskeyRRAt builds a fresh apex DNSKEY record for zone from k's key
// material -- k itself may carry a different owner name (e.g. one just
// fetched live via an ordinary query, which sets it from the query
// name), which this deliberately discards in favor of zone.
func dnskeyRRAt(zone string, k *dns.DNSKEY) *dns.DNSKEY {
	return &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     k.Flags, Protocol: k.Protocol, Algorithm: k.Algorithm, PublicKey: k.PublicKey,
	}
}

// sameDNSKEY reports whether a and b are the same key -- compared by
// public key material and algorithm alone, the two fields that actually
// identify "the same key" independent of which zone name or flags a
// given copy happens to carry (e.g. one just fetched live via a query
// versus one loaded from a local file).
func sameDNSKEY(a, b *dns.DNSKEY) bool {
	return a.Algorithm == b.Algorithm && a.PublicKey == b.PublicKey
}

// buildDNSKEYRRsetPush builds an RFC 2136 UPDATE message that changes a
// zone's served apex DNSKEY RRset from current to want: an RFC 2136
// §2.5.4 delete for each record in current no longer in want, followed
// by every record in want -- new or unchanged -- re-asserted as an
// ordinary add, together with one fresh RRSIG (signed by signer/
// signerPriv) covering exactly want.
//
// Re-asserting every unchanged record isn't redundant, and skipping it
// is the mistake this function exists to prevent: an RRSIG covers its
// whole RRset as one unit, never a single record added or removed
// independently of the rest, and this package's server never holds a
// private key to recompute one itself (SAZU's whole premise is that it
// never needs to). So whichever client changes this RRset's membership
// -- BuildAddZSKPush, BuildRetireZSKPush, BuildKSKRolloverPush, all
// built on this -- must present, and sign, the complete new membership
// every time, not just the delta, or the signature ends up covering
// content that no longer matches what's actually served (see
// SAZU-PLAN.md for the concrete failure this was found from: a stale
// RRSIG left covering a DNSKEY set that no longer existed, which a real
// validating resolver would see as a bogus signature over the entire
// zone).
func buildDNSKEYRRsetPush(zone string, current, want []*dns.DNSKEY, signer *dns.DNSKEY, signerPriv crypto.Signer) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	m.Opcode = dns.OpcodeUpdate

	var removed []dns.RR
	for _, k := range current {
		still := false
		for _, w := range want {
			if sameDNSKEY(k, w) {
				still = true
				break
			}
		}
		if !still {
			removed = append(removed, dnskeyRRAt(zone, k))
		}
	}
	if len(removed) > 0 {
		m.Remove(removed)
	}

	wantRRs := make([]dns.RR, len(want))
	for i, k := range want {
		wantRRs[i] = dnskeyRRAt(zone, k)
	}
	now := time.Now()
	signed, err := SignZoneContent(wantRRs, signer, signerPriv, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
	if err != nil {
		return nil, err
	}
	m.Insert(signed)
	return m, nil
}

// BuildAddZSKPush builds an RFC 2136 UPDATE message that registers
// newZSK on top of a zone's existing DNSKEY RRset, re-signing the
// complete resulting set (current plus newZSK) as one RRSIG -- see
// buildDNSKEYRRsetPush's doc comment for why re-signing only newZSK
// alone, the way an earlier version of this package did, is wrong.
//
// current is every DNSKEY record the zone currently serves -- a live
// query (see cmd/sazuctl's fetchCurrentDNSKEYs), since this package
// tracks no server-side state of its own and has no other way to know
// it. signer/signerPriv is whichever key is authenticating and content-
// signing this transaction: ordinarily the KSK, but this package's own
// convention (see keys.go's KeyRole doc comment) also allows an
// already-authorized ZSK to register another.
//
// The transaction itself (SIG(0), via SignUpdate) must also be signed
// by signer.
func BuildAddZSKPush(zone string, current []*dns.DNSKEY, newZSK *dns.DNSKEY, signer *dns.DNSKEY, signerPriv crypto.Signer) (*dns.Msg, error) {
	want := append(append([]*dns.DNSKEY{}, current...), newZSK)
	return buildDNSKEYRRsetPush(zone, current, want, signer, signerPriv)
}

// BuildRetireZSKPush builds an RFC 2136 UPDATE message that removes
// retiredZSK from a zone's DNSKEY RRset, re-signing the complete
// remaining set -- BuildAddZSKPush's inverse; see its doc comment and
// buildDNSKEYRRsetPush's for why the remaining, unchanged records must
// be re-signed too, not just deleted from.
//
// current and signer/signerPriv are exactly as in BuildAddZSKPush.
func BuildRetireZSKPush(zone string, current []*dns.DNSKEY, retiredZSK *dns.DNSKEY, signer *dns.DNSKEY, signerPriv crypto.Signer) (*dns.Msg, error) {
	var want []*dns.DNSKEY
	for _, k := range current {
		if !sameDNSKEY(k, retiredZSK) {
			want = append(want, k)
		}
	}
	return buildDNSKEYRRsetPush(zone, current, want, signer, signerPriv)
}

// BuildKSKRolloverPush builds an RFC 2136 UPDATE message that replaces
// a zone's KSK: removes oldKSK and installs newKSK (which self-signs,
// same as BuildTrustPush's first contact), re-signing the complete
// resulting DNSKEY RRset -- every currently registered ZSK, unchanged,
// plus newKSK. See buildDNSKEYRRsetPush's doc comment for why the
// unchanged ZSKs must be re-signed too, not just newKSK alone: without
// this, a rollover leaves both the old KSK's record (never explicitly
// removed, so it lingers in what's actually served) and a signature
// that covers only the new key in isolation, matching neither the old
// nor the new complete set.
//
// current is every DNSKEY record the zone currently serves (see
// BuildAddZSKPush). The transaction itself (SIG(0), via SignUpdate)
// must also be signed by newKSK -- a rollover, like first contact, only
// ever trusts a SEP-flagged candidate to authenticate it.
func BuildKSKRolloverPush(zone string, current []*dns.DNSKEY, oldKSK, newKSK *dns.DNSKEY, newKSKPriv crypto.Signer) (*dns.Msg, error) {
	var want []*dns.DNSKEY
	for _, k := range current {
		if !sameDNSKEY(k, oldKSK) {
			want = append(want, k)
		}
	}
	want = append(want, newKSK)
	return buildDNSKEYRRsetPush(zone, current, want, newKSK, newKSKPriv)
}

// BuildContentPush builds an RFC 2136 UPDATE message for a routine,
// ZSK-only zone-content push: the zone's complete content (soa, rrs, and
// a freshly computed denial-of-existence chain), signed entirely by zsk
// -- and carrying no DNSKEY record at all, since publish-trust (see
// BuildTrustPush) already established this ZSK's DNSKEY server-side. The
// transaction itself is also signed by zsk (via SignUpdate, by the
// caller) -- this push never needs the KSK for anything.
//
// previousSOA behaves exactly as in BuildFullZonePush.
//
// Uses plain NSEC (BuildNSECChain). See BuildContentPushNSEC3 for the
// RFC 5155 NSEC3 alternative.
func BuildContentPush(zone string, soa *dns.SOA, rrs []dns.RR, zsk *dns.DNSKEY, zskSigner crypto.Signer, previousSOA *dns.SOA) (*dns.Msg, error) {
	return buildContentPush(zone, soa, rrs, zsk, zskSigner, previousSOA, BuildNSECChain)
}

// BuildContentPushNSEC3 is BuildContentPush's RFC 5155 NSEC3 equivalent
// -- see BuildNSEC3Chain and NSEC3Options.
func BuildContentPushNSEC3(zone string, soa *dns.SOA, rrs []dns.RR, zsk *dns.DNSKEY, zskSigner crypto.Signer, previousSOA *dns.SOA, opts NSEC3Options) (*dns.Msg, error) {
	return buildContentPush(zone, soa, rrs, zsk, zskSigner, previousSOA, func(soa *dns.SOA, adds []dns.RR) []dns.RR {
		return BuildNSEC3Chain(soa, adds, opts)
	})
}

func buildContentPush(zone string, soa *dns.SOA, rrs []dns.RR, zsk *dns.DNSKEY, zskSigner crypto.Signer, previousSOA *dns.SOA, denialChain func(*dns.SOA, []dns.RR) []dns.RR) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	m.Opcode = dns.OpcodeUpdate

	if previousSOA != nil {
		m.Used([]dns.RR{previousSOA})
	}

	zskRR := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: soa.Hdr.Ttl},
		Flags:     zsk.Flags, Protocol: zsk.Protocol, Algorithm: zsk.Algorithm, PublicKey: zsk.PublicKey,
	}

	adds := make([]dns.RR, 0, len(rrs)+2)
	adds = append(adds, soa)
	adds = append(adds, rrs...)
	adds = append(adds, denialChain(soa, adds)...)

	now := time.Now()
	// zskRR is never inserted into adds -- it exists only so
	// SignZoneContentSplit has a key tag/name/algorithm to sign with; the
	// DNSKEY record itself isn't part of this push at all. The ksk/
	// kskSigner slots are nil because adds never contains a DNSKEY group
	// for them to apply to (see SignZoneContentSplit's doc comment).
	signed, err := SignZoneContentSplit(adds, nil, nil, zskRR, zskSigner, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
	if err != nil {
		return nil, err
	}
	m.Insert(signed)
	return m, nil
}

func buildFullZonePushSplit(zone string, soa *dns.SOA, rrs []dns.RR, ksk *dns.DNSKEY, kskSigner crypto.Signer, zsk *dns.DNSKEY, zskSigner crypto.Signer, previousSOA *dns.SOA, denialChain func(*dns.SOA, []dns.RR) []dns.RR) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	m.Opcode = dns.OpcodeUpdate

	if previousSOA != nil {
		m.Used([]dns.RR{previousSOA})
	}

	kskRR := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: soa.Hdr.Ttl},
		Flags:     ksk.Flags,
		Protocol:  ksk.Protocol,
		Algorithm: ksk.Algorithm,
		PublicKey: ksk.PublicKey,
	}
	contentKeyRR, contentSigner := kskRR, kskSigner

	adds := make([]dns.RR, 0, len(rrs)+3)
	adds = append(adds, kskRR)
	if zsk != nil {
		zskRR := &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: soa.Hdr.Ttl},
			Flags:     zsk.Flags,
			Protocol:  zsk.Protocol,
			Algorithm: zsk.Algorithm,
			PublicKey: zsk.PublicKey,
		}
		adds = append(adds, zskRR)
		contentKeyRR, contentSigner = zskRR, zskSigner
	}
	adds = append(adds, soa)
	adds = append(adds, rrs...)
	adds = append(adds, denialChain(soa, adds)...)

	now := time.Now()
	signed, err := SignZoneContentSplit(adds, kskRR, kskSigner, contentKeyRR, contentSigner, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
	if err != nil {
		return nil, err
	}
	m.Insert(signed)

	return m, nil
}
