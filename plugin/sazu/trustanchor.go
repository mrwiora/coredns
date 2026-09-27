// Package sazu implements SAZU (Self-Authenticated Zone Update): a
// split-signing DNSSEC scheme where a customer's own signer holds the
// private key, and this server only ever accepts already-signed zone
// updates, authenticated via SIG(0) (RFC 2931) carried on RFC 2136 dynamic
// UPDATE messages. See the protocol specification (readme.md in
// github.com/mrwiora/sazu) for the full protocol, and this repo's own
// plugin/sazu/docs/SAZU-PLAN.md for exactly what of it this port
// implements. Registered as a real CoreDNS plugin (plugin.cfg,
// setup.go) -- `sazu ZONES...` in a Corefile.
package sazu

import (
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// TrustAnchor pins one root-zone KSK by its RFC 4034 §5.1.4 digest -- the
// same construction a DS record uses, just carried here as a hex string
// because the root has no parent to publish one. This is the base case
// chain-of-trust validation bootstraps from.
type TrustAnchor struct {
	KeyTag    uint16
	Algorithm uint8
	// DigestType is the DS digest algorithm of DigestHex: SHA-256 (2) or
	// SHA-384 (4). Zero means SHA-256, which every built-in anchor uses.
	DigestType uint8
	// DigestHex is the digest of (root name "." || DNSKEY RDATA),
	// hex-encoded.
	DigestHex string
}

// RootTrustAnchors are the built-in IANA root zone KSKs, used unless a
// trust anchor file is configured (the sazu plugin's trust_anchor
// directive, sazu-watchd's -trust-anchor flag). Both keys IANA publishes
// in https://data.iana.org/root-anchors/root-anchors.xml are listed so
// validation keeps working across the root KSK rollover from KSK-2017
// to KSK-2024: validation needs the key that actually *signs* the root
// DNSKEY RRset to be anchored, not merely one that is published in it.
//
// A built-in list can only ever be as current as the build it's in. For
// anything long-lived, configure a trust anchor file kept up to date
// independently (e.g. by unbound-anchor, which implements RFC 5011) --
// see LoadTrustAnchors.
func RootTrustAnchors() []TrustAnchor {
	return []TrustAnchor{
		{
			// KSK-2017.
			KeyTag:    20326,
			Algorithm: dns.RSASHA256,
			DigestHex: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
		},
		{
			// KSK-2024. TODO(verify): this digest was added without network
			// access to IANA; check it against root-anchors.xml before
			// relying on it. A wrong value can't match any key -- it would
			// only fail to help once KSK-2024 signs the root.
			KeyTag:    38696,
			Algorithm: dns.RSASHA256,
			DigestHex: "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
		},
	}
}

// Matches reports whether key is the KSK this trust anchor pins. It
// verifies the real digest of the key -- not just key tag, algorithm,
// and the SEP (KSK) flag, which alone would accept any key an attacker
// chose with the right metadata but different key material.
func (a TrustAnchor) Matches(key *dns.DNSKEY) bool {
	if key == nil {
		return false
	}
	if key.KeyTag() != a.KeyTag || key.Algorithm != a.Algorithm || key.Flags&dns.SEP == 0 {
		return false
	}
	digestType := a.DigestType
	if digestType == 0 {
		digestType = dns.SHA256
	}
	ds := key.ToDS(digestType)
	if ds == nil {
		return false
	}
	return strings.EqualFold(ds.Digest, a.DigestHex)
}

// LoadTrustAnchors reads root trust anchors from a zone-file-format file
// of DS and/or DNSKEY records for the root (".") -- the format
// unbound-anchor maintains its root.key file in, and the format IANA's
// root-anchors.xml translates to directly. DS records must use SHA-256
// or SHA-384; a DNSKEY is anchored by its SHA-256 digest. Records for
// any other owner, and any other type, are an error rather than silently
// ignored: a typo in a security-critical file should be loud.
func LoadTrustAnchors(path string) ([]TrustAnchor, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var anchors []TrustAnchor
	zp := dns.NewZoneParser(f, ".", path)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if rr.Header().Name != "." {
			return nil, fmt.Errorf("%s: trust anchor for %q, only the root (\".\") is supported", path, rr.Header().Name)
		}
		switch r := rr.(type) {
		case *dns.DS:
			if r.DigestType != dns.SHA256 && r.DigestType != dns.SHA384 {
				return nil, fmt.Errorf("%s: DS for key tag %d uses digest type %d; only SHA-256 (2) and SHA-384 (4) are accepted", path, r.KeyTag, r.DigestType)
			}
			anchors = append(anchors, TrustAnchor{KeyTag: r.KeyTag, Algorithm: r.Algorithm, DigestType: r.DigestType, DigestHex: r.Digest})
		case *dns.DNSKEY:
			if r.Flags&dns.SEP == 0 {
				return nil, fmt.Errorf("%s: DNSKEY with key tag %d is not a KSK (SEP flag unset)", path, r.KeyTag())
			}
			ds := r.ToDS(dns.SHA256)
			anchors = append(anchors, TrustAnchor{KeyTag: r.KeyTag(), Algorithm: r.Algorithm, DigestType: dns.SHA256, DigestHex: ds.Digest})
		default:
			return nil, fmt.Errorf("%s: unexpected %s record; a trust anchor file holds DS or DNSKEY records only", path, dns.TypeToString[rr.Header().Rrtype])
		}
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(anchors) == 0 {
		return nil, fmt.Errorf("%s: no trust anchors found", path)
	}
	return anchors, nil
}
