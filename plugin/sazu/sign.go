package sazu

import (
	"crypto"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// SignZoneContent signs every authoritative RRset in rrs (grouped by
// owner name and type) with one key: SignZoneContentSplit with the same
// key as KSK and ZSK. Returns rrs plus one RRSIG per signed RRset, in the
// order the RRsets first appear. dnskeyRR must be signer's public key.
func SignZoneContent(rrs []dns.RR, dnskeyRR *dns.DNSKEY, signer crypto.Signer, inception, expiration time.Time) ([]dns.RR, error) {
	return SignZoneContentSplit(rrs, dnskeyRR, signer, dnskeyRR, signer, inception, expiration)
}

// SignZoneContentSplit signs the DNSKEY RRset with ksk and every other
// authoritative RRset with zsk (RFC 4034's KSK/ZSK convention). The NS
// RRset at a delegation and glue below it are left unsigned (RFC 4035
// §2.2). kskSigner is unused when rrs holds no DNSKEY RRset.
func SignZoneContentSplit(rrs []dns.RR, ksk *dns.DNSKEY, kskSigner crypto.Signer, zsk *dns.DNSKEY, zskSigner crypto.Signer, inception, expiration time.Time) ([]dns.RR, error) {
	groups := groupRRsets(rrs)
	apex := zoneApex(rrs)
	cuts := zoneCuts(apex, rrs)
	out := make([]dns.RR, 0, len(rrs)+len(groups))
	for _, group := range groups {
		out = append(out, group...)
		h := group[0].Header()
		if !isAuthoritativeRRset(h.Name, h.Rrtype, apex, cuts) {
			continue // delegation NS and glue stay unsigned (RFC 4035 §2.2)
		}
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

// signOneRRset signs one RRset. The RRSIG's own TTL is set to the
// RRset's (RFC 4034 §3): miekg/dns's Sign sets only the Original TTL
// field, and a zero-TTL RRSIG is dropped from resolver caches mid-
// validation, which makes validation fail.
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
//   - every non-RRSIG Add-shaped RRset among ops that is the zone's
//     authoritative data must have at least one covering RRSIG, also
//     present in ops, that verifies and is within its validity window at
//     now. The NS RRset at a delegation point and glue below it are not
//     the zone's authoritative data and must not be signed (RFC 4035
//     §2.2); the zone cuts are those of the pushed content;
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
	apex := zoneApex(adds)
	cuts := zoneCuts(apex, adds)
	for _, group := range groups {
		h := group[0].Header()
		if !isAuthoritativeRRset(h.Name, h.Rrtype, apex, cuts) {
			continue
		}
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
		if !isAuthoritativeRRset(sig.Hdr.Name, sig.TypeCovered, apex, cuts) {
			return "", fmt.Errorf("sazu: RRSIG at %s covers %s, which is delegation or glue data and must not be signed (RFC 4035 §2.2)",
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
