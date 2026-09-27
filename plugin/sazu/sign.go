package sazu

import (
	"crypto"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// SignZoneContent produces an RFC 4034 RRSIG for every RRset in rrs
// (grouped by owner name + type), signed with signer -- SAZU's original,
// still-default single-key model (§9.1): the one key that authenticates
// a push over SIG(0) is the same key that signs the zone content itself,
// so there is no separate DNSSEC signing step or key to manage. The
// DNSKEY RRset gets signed exactly the same way as everything else here
// (a self-signature, since it's just another RRset in rrs), which is why
// this single-key model doesn't need a KSK/ZSK split to produce a
// validly self-signed DNSKEY RRset. A zone that registers an optional
// ZSK (see keys.go) instead uses SignZoneContentSplit, below; this
// function is simply that one called with the same key on both sides,
// preserved as its own entry point so every existing single-key caller
// and test is completely unaffected by the ZSK addition.
//
// Returns rrs unchanged plus one RRSIG per distinct (name, type) group,
// in the order those groups first appeared. Pass a signer/dnskeyRR pair
// that actually match (dnskeyRR.KeyTag() must equal what signer will
// produce) -- this function does not check that itself; VerifySignedRRsets
// is what a receiver uses to confirm it.
func SignZoneContent(rrs []dns.RR, dnskeyRR *dns.DNSKEY, signer crypto.Signer, inception, expiration time.Time) ([]dns.RR, error) {
	return SignZoneContentSplit(rrs, dnskeyRR, signer, dnskeyRR, signer, inception, expiration)
}

// SignZoneContentSplit is SignZoneContent's ZSK-aware generalization: it
// signs the DNSKEY RRset specifically with ksk/kskSigner -- RFC 4034's
// own convention, that the key-signing key signs the key set -- and
// every other RRset with zsk/zskSigner, the key designated to sign
// ordinary zone content. Passing the same key/signer pair for both
// reproduces SignZoneContent's original behavior exactly (byte-for-byte:
// it's the same code path with the same key on both sides), which is
// what SignZoneContent itself now does. rrs need not actually contain a
// DNSKEY RRset -- an ordinary publish-zone content push, signed entirely
// with the active ZSK, never does -- in which case kskSigner is simply
// never used.
func SignZoneContentSplit(rrs []dns.RR, ksk *dns.DNSKEY, kskSigner crypto.Signer, zsk *dns.DNSKEY, zskSigner crypto.Signer, inception, expiration time.Time) ([]dns.RR, error) {
	groups := groupRRsets(rrs)
	out := make([]dns.RR, 0, len(rrs)+len(groups))
	for _, group := range groups {
		out = append(out, group...)
		dnskeyRR, signer := zsk, zskSigner
		if group[0].Header().Rrtype == dns.TypeDNSKEY {
			dnskeyRR, signer = ksk, kskSigner
		}
		sig, err := signOneRRset(group, dnskeyRR, signer, inception, expiration)
		if err != nil {
			return nil, err
		}
		out = append(out, sig)
	}
	return out, nil
}

// rrsetKey identifies one RRset: owner name (lowercased -- names are
// already stored lowercase throughout this package, but grouping is
// cheap insurance against a caller that didn't) plus type.
type rrsetKey struct {
	name  string
	rtype uint16
}

// groupRRsets partitions rrs into RRsets by (owner name, type), preserving
// the order each group first appears in -- signing (and later, serving)
// wants records processed one RRset at a time, not one record at a time.
func groupRRsets(rrs []dns.RR) [][]dns.RR {
	var order []rrsetKey
	groups := make(map[rrsetKey][]dns.RR)
	for _, rr := range rrs {
		h := rr.Header()
		k := rrsetKey{name: strings.ToLower(h.Name), rtype: h.Rrtype}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], rr)
	}
	result := make([][]dns.RR, len(order))
	for i, k := range order {
		result[i] = groups[k]
	}
	return result
}

// signOneRRset signs one RRset, filling in the RRSIG fields Sign itself
// doesn't derive from the RRset (TypeCovered, Labels, OrigTtl, and the
// owner/class/type of the RRSIG record are all set by Sign itself from
// rrset[0]'s header) -- with one exception. Sign sets OrigTtl (the RDATA
// field carried inside the signed data itself, per RFC 4034 §3.1.5) but
// deliberately never touches Hdr.Ttl, the RRSIG record's own wire TTL:
// miekg/dns leaves that to the caller. RFC 4034 §3 requires it to match
// the covered RRset's TTL exactly ("the TTL value of an RRSIG RR MUST
// match the TTL value of the RRset it covers"); left unset, it silently
// defaults to zero. A zero-TTL record isn't just a hygiene nit here --
// found the hard way against a real validating resolver (Unbound):
// treating a just-received RRSIG as instantly-expired and dropping it
// from its cache mid-validation corrupts its own multi-step recursive
// validation state, producing an opaque, misleading SERVFAIL
// ("Cannot retrieve DS for signature") for answers that are otherwise
// completely valid.
func signOneRRset(rrset []dns.RR, dnskeyRR *dns.DNSKEY, signer crypto.Signer, inception, expiration time.Time) (*dns.RRSIG, error) {
	sig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Ttl: rrset[0].Header().Ttl},
		Algorithm:  dnskeyRR.Algorithm,
		KeyTag:     dnskeyRR.KeyTag(),
		SignerName: dnskeyRR.Hdr.Name,
		Inception:  uint32(inception.Unix()),
		Expiration: uint32(expiration.Unix()),
	}
	if err := sig.Sign(signer, rrset); err != nil {
		h := rrset[0].Header()
		return nil, fmt.Errorf("signing %s/%s: %w", h.Name, dns.TypeToString[h.Rrtype], err)
	}
	return sig, nil
}

// VerifySignedRRsets checks that every non-RRSIG Add-shaped RRset among
// ops has at least one covering RRSIG, also present in ops, that
// verifies against any key in candidates and is within its validity
// window at now. It is VerifySignedRRsetsSplit with no separate
// DNSKEY-RRset signer: every RRset, the DNSKEY RRset included, may be
// covered by any candidate. serveUpdate itself never uses this form --
// see VerifySignedRRsetsSplit for the rule it enforces instead.
func VerifySignedRRsets(candidates []*dns.DNSKEY, ops []dns.RR, zclass uint16, now time.Time) (string, error) {
	return VerifySignedRRsetsSplit(candidates, nil, ops, zclass, now)
}

// VerifySignedRRsetsSplit is the check serveUpdate runs on every update
// (content verification is mandatory; SIG(0) alone only proves who sent
// an update, never that what it carries will validate once served):
//
//   - every non-RRSIG Add-shaped RRset among ops must have at least one
//     covering RRSIG, also present in ops, that verifies and is within
//     its validity window at now;
//   - an apex DNSKEY RRset may only be covered by a key in
//     dnskeySigners (the zone's KSK), every other RRset by any key in
//     candidates. A validating resolver accepts a DNSKEY RRset only
//     when it is signed by a key the parent's DS matches (RFC 4035
//     §5.2) -- accepting a ZSK's RRSIG over it here would store and
//     serve a zone this server considers valid but every validating
//     resolver treats as bogus. nil dnskeySigners means "same as
//     candidates" (VerifySignedRRsets' single-key behavior);
//   - every Add-shaped RRSIG in ops must itself cover an RRset added by
//     the same update and verify against a key permitted for that
//     RRset. Without this, an extra, unverifiable RRSIG could ride along
//     next to a valid one and be stored and served beside it -- or
//     replace an earlier valid signature by the same signer (see
//     replaceRRSIG).
//
// Delete-shaped ops are ignored -- there's no established convention
// for "signing" a deletion. Ops are otherwise expected to be
// wire-accurate (Class/Rdlength reflecting what was actually unpacked),
// the same precondition EvaluatePrerequisites and ApplyUpdateOps
// document. Callers must additionally make sure the added records are
// the complete RRset as it will be served (serveUpdate does for the
// DNSKEY RRset, the only one an update can change without replacing the
// whole zone), since the signature is verified over the records the
// update carries.
//
// On failure, also returns a SAZU status code when the failure is
// specific enough to warrant one: statusErrExpiredSignature if a
// covering RRSIG was found that is otherwise completely legitimate but
// simply falls outside its own inception/expiration window, as opposed
// to "" for the more generic "no valid RRSIG at all" case.
func VerifySignedRRsetsSplit(candidates, dnskeySigners []*dns.DNSKEY, ops []dns.RR, zclass uint16, now time.Time) (string, error) {
	if dnskeySigners == nil {
		dnskeySigners = candidates
	}
	signersFor := func(rrtype uint16) []*dns.DNSKEY {
		if rrtype == dns.TypeDNSKEY {
			return dnskeySigners
		}
		return candidates
	}

	adds := make([]dns.RR, 0, len(ops))
	sigs := make([]*dns.RRSIG, 0)
	for _, rr := range ops {
		h := rr.Header()
		if h.Class != zclass {
			continue
		}
		if sig, ok := rr.(*dns.RRSIG); ok {
			sigs = append(sigs, sig)
			continue
		}
		adds = append(adds, rr)
	}

	groups := groupRRsets(adds)
	for _, group := range groups {
		h := group[0].Header()
		ok, expired := anySignatureVerifies(group, h.Rrtype, sigs, signersFor(h.Rrtype), now)
		if !ok {
			if expired {
				return statusErrExpiredSignature, fmt.Errorf(
					"sazu: RRSIG covering %s/%s is outside its validity window", h.Name, dns.TypeToString[h.Rrtype])
			}
			return "", fmt.Errorf("sazu: no valid RRSIG covers %s/%s", h.Name, dns.TypeToString[h.Rrtype])
		}
	}

	for _, sig := range sigs {
		var group []dns.RR
		for _, g := range groups {
			if g[0].Header().Rrtype == sig.TypeCovered && strings.EqualFold(g[0].Header().Name, sig.Hdr.Name) {
				group = g
				break
			}
		}
		if group == nil {
			return "", fmt.Errorf("sazu: RRSIG at %s covers %s, but this update adds no such RRset",
				sig.Hdr.Name, dns.TypeToString[sig.TypeCovered])
		}
		verified := false
		for _, k := range signersFor(sig.TypeCovered) {
			if sig.KeyTag == k.KeyTag() && sig.Algorithm == k.Algorithm && sig.Verify(k, group) == nil {
				verified = true
				break
			}
		}
		if !verified {
			return "", fmt.Errorf("sazu: RRSIG at %s over %s (key tag %d) does not verify against a key allowed to sign that RRset",
				sig.Hdr.Name, dns.TypeToString[sig.TypeCovered], sig.KeyTag)
		}
	}
	return "", nil
}

// anySignatureVerifies reports whether any sig in sigs both covers rrset
// and actually verifies against any key in candidates within its
// validity window (ok), and separately whether a cryptographically
// valid but expired (or not-yet-valid) match was seen along the way
// (expired) -- checked in that order (crypto first) specifically so a
// signature that fails crypto for its own reasons is never mistaken for
// merely expired.
func anySignatureVerifies(rrset []dns.RR, covered uint16, sigs []*dns.RRSIG, candidates []*dns.DNSKEY, now time.Time) (ok, expired bool) {
	for _, sig := range sigs {
		if sig.TypeCovered != covered || !strings.EqualFold(sig.Hdr.Name, rrset[0].Header().Name) {
			continue
		}
		for _, candidate := range candidates {
			if sig.KeyTag != candidate.KeyTag() || sig.Algorithm != candidate.Algorithm {
				continue
			}
			if err := sig.Verify(candidate, rrset); err != nil {
				continue
			}
			if !sig.ValidityPeriod(now) {
				expired = true
				continue
			}
			return true, false
		}
	}
	return false, expired
}
