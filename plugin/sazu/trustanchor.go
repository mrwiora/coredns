package sazu

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"time"

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
			// KSK-2024.
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

// LoadTrustAnchors reads root trust anchors from path, in either of two
// formats:
//
//   - IANA's root-anchors.xml (RFC 7958, as updated by RFC 9718): every
//     KeyDigest valid now (validFrom reached, validUntil not yet) with a
//     SHA-256 or SHA-384 digest;
//   - zone file format holding DS and/or DNSKEY records for the root
//     ("."), the format unbound-anchor (RFC 5011) maintains its root.key
//     in. DS records must use SHA-256 or SHA-384; a DNSKEY is anchored by
//     its SHA-256 digest.
//
// Anything unexpected is an error rather than silently ignored: a typo
// in a security-critical file should be loud.
func LoadTrustAnchors(path string) ([]TrustAnchor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if trimmed := bytes.TrimSpace(data); bytes.HasPrefix(trimmed, []byte("<")) {
		return parseRootAnchorsXML(path, data, time.Now())
	}

	var anchors []TrustAnchor
	zp := dns.NewZoneParser(bytes.NewReader(data), ".", path)
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

// rootAnchorsXML is the RFC 7958 §2.1 document.
type rootAnchorsXML struct {
	XMLName    xml.Name `xml:"TrustAnchor"`
	Zone       string   `xml:"Zone"`
	KeyDigests []struct {
		ID         string `xml:"id,attr"`
		ValidFrom  string `xml:"validFrom,attr"`
		ValidUntil string `xml:"validUntil,attr"`
		KeyTag     uint16 `xml:"KeyTag"`
		Algorithm  uint8  `xml:"Algorithm"`
		DigestType uint8  `xml:"DigestType"`
		Digest     string `xml:"Digest"`
	} `xml:"KeyDigest"`
}

// parseRootAnchorsXML returns the KeyDigests of an RFC 7958 document
// that are valid at now (RFC 7958 §2.3).
func parseRootAnchorsXML(path string, data []byte, now time.Time) ([]TrustAnchor, error) {
	var doc rootAnchorsXML
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if strings.TrimSpace(doc.Zone) != "." {
		return nil, fmt.Errorf("%s: trust anchors for %q, only the root (\".\") is supported", path, doc.Zone)
	}
	var anchors []TrustAnchor
	for _, kd := range doc.KeyDigests {
		from, err := time.Parse(time.RFC3339, kd.ValidFrom)
		if err != nil {
			return nil, fmt.Errorf("%s: KeyDigest %s: validFrom: %w", path, kd.ID, err)
		}
		if now.Before(from) {
			continue
		}
		if kd.ValidUntil != "" {
			until, err := time.Parse(time.RFC3339, kd.ValidUntil)
			if err != nil {
				return nil, fmt.Errorf("%s: KeyDigest %s: validUntil: %w", path, kd.ID, err)
			}
			if !now.Before(until) {
				continue
			}
		}
		if kd.DigestType != dns.SHA256 && kd.DigestType != dns.SHA384 {
			continue
		}
		anchors = append(anchors, TrustAnchor{KeyTag: kd.KeyTag, Algorithm: kd.Algorithm, DigestType: kd.DigestType, DigestHex: strings.TrimSpace(kd.Digest)})
	}
	if len(anchors) == 0 {
		return nil, fmt.Errorf("%s: no currently valid SHA-256 or SHA-384 KeyDigest", path)
	}
	return anchors, nil
}
