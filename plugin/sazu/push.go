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
