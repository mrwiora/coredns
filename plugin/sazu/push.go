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
// and every other RR it contains: the zone content a full push (§5.3)
// sends.
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

// BuildFullZonePush builds a full-zone push (§5.3) signed with one key:
// the key as the apex DNSKEY, the SOA, every record in rrs and an NSEC
// chain over all of it, each RRset carrying an RRSIG by that key (SIG(0)
// authenticates the transaction; the RRSIGs are what validating
// resolvers check once it's served).
//
// previousSOA, if non-nil, adds an RFC 2136 §2.4.2 "RRset exists, value
// dependent" prerequisite on it, so the push applies only if that is
// still the served SOA. Pass nil for a zone's first push.
//
// Only a full push carries a denial-of-existence chain, since only it
// sees every name in the zone; the server refuses partial content pushes.
func BuildFullZonePush(zone string, soa *dns.SOA, rrs []dns.RR, candidateKey *dns.DNSKEY, signer crypto.Signer, previousSOA *dns.SOA) (*dns.Msg, error) {
	return BuildFullZonePushSplit(zone, soa, rrs, candidateKey, signer, nil, nil, previousSOA)
}

// BuildFullZonePushSplit is BuildFullZonePush with a separate ZSK: ksk
// is added to the apex DNSKEY RRset and signs it; zsk, if non-nil, is
// added too and signs every other RRset. With zsk nil, ksk signs
// everything.
//
// Uses NSEC (BuildNSECChain); see BuildFullZonePushSplitNSEC3 for NSEC3.
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
		Hdr:   dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: ksk.Flags, Protocol: ksk.Protocol, Algorithm: ksk.Algorithm, PublicKey: ksk.PublicKey,
	}
	zskRR := &dns.DNSKEY{
		Hdr:   dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: zsk.Flags, Protocol: zsk.Protocol, Algorithm: zsk.Algorithm, PublicKey: zsk.PublicKey,
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
		Hdr:   dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: k.Flags, Protocol: k.Protocol, Algorithm: k.Algorithm, PublicKey: k.PublicKey,
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

// buildDNSKEYRRsetPush builds an UPDATE that changes a zone's apex
// DNSKEY RRset from current to want: an RFC 2136 §2.5.4 delete for each
// record of current not in want, then every record of want -- new or
// unchanged -- as an add, with one RRSIG by signer over exactly want. An
// RRSIG covers the whole RRset and the server never signs, so the client
// must always send and sign the complete new RRset, never just the delta.
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
// buildDNSKEYRRsetPush.
//
// current is every DNSKEY record the zone currently serves -- a live
// query (see cmd/sazuctl's fetchCurrentDNSKEYs), since this package
// tracks no server-side state of its own and has no other way to know
// it. signer/signerPriv must be the zone's KSK: it signs the DNSKEY
// RRset, which a validating resolver only accepts from a key the
// parent's DS matches (RFC 4035 §5.2), and the server refuses a DNSKEY
// RRset change authenticated or signed by anything else.
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

// BuildDecommissionPush builds an RFC 2136 UPDATE message that requests a
// zone's complete removal -- KSK, every ZSK, all content and its chain,
// and the contact registration -- rather than a change to any of them.
// It carries nothing but the decommission.go marker: no DNSKEY, no
// content, since nothing about the zone's key state or content is being
// modified, it's simply ceasing to exist. Like BuildContactOp, this is
// deliberately not run through SignZoneContent -- the directive isn't
// zone content and is never itself DNSSEC-signed. The transaction itself
// (SIG(0), via SignUpdate, by the caller) must be signed by the zone's
// KSK specifically -- handler.go refuses a decommission directive
// authenticated by anything else, the same requirement first contact and
// a rollover already have.
func BuildDecommissionPush(zone string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	m.Opcode = dns.OpcodeUpdate
	m.Insert([]dns.RR{BuildDecommissionOp(zone)})
	return m
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
		Hdr:   dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: soa.Hdr.Ttl},
		Flags: zsk.Flags, Protocol: zsk.Protocol, Algorithm: zsk.Algorithm, PublicKey: zsk.PublicKey,
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
