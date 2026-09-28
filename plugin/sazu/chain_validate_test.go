package sazu

import (
	"crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// serveDNSKEYAnswer starts a UDP DNS server on loopback that answers any
// DNSKEY query authoritatively with answer, and returns its address.
func serveDNSKEYAnswer(t *testing.T, answer []dns.RR) string {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = answer
		w.WriteMsg(m) //nolint:errcheck
	})
	started := make(chan struct{})
	srv := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux, NotifyStartedFunc: func() { close(started) }}
	go srv.ListenAndServe() //nolint:errcheck
	<-started
	t.Cleanup(func() { srv.Shutdown() }) //nolint:errcheck
	return srv.PacketConn.LocalAddr().String()
}

func dnskeySetWithSig(t *testing.T, zone string, keys []*dns.DNSKEY, signerKey *dns.DNSKEY, signer crypto.Signer) []dns.RR {
	t.Helper()
	var rrs []dns.RR
	for _, k := range keys {
		rrs = append(rrs, k)
	}
	return append(rrs, signRRset(t, zone, rrs, signerKey, signer, time.Now()))
}

// TestFetchAndVerifyDNSKEYRequiresTheDSMatchedKeyToSign: whoever answers
// the DNSKEY query can add a key of their own to the RRset. The RRset
// must be signed by the key the trusted DS matches, not by any key in
// it -- otherwise the injected key would be trusted to vouch for
// everything below this zone.
func TestFetchAndVerifyDNSKEYRequiresTheDSMatchedKeyToSign(t *testing.T) {
	realKSK, realSigner := genKey(t, "example.", true)
	injected, injectedSigner := genKey(t, "example.", true)
	trustedDS := []*dns.DS{realKSK.ToDS(dns.SHA256)}
	v := &Validator{Client: &dns.Client{Timeout: 2 * time.Second}}

	forged := serveDNSKEYAnswer(t, dnskeySetWithSig(t, "example.", []*dns.DNSKEY{realKSK, injected}, injected, injectedSigner))
	if _, err := v.fetchAndVerifyDNSKEY("example.", []string{forged}, trustedDS); err == nil {
		t.Fatalf("expected a DNSKEY RRset signed only by an injected key to be rejected")
	}

	genuine := serveDNSKEYAnswer(t, dnskeySetWithSig(t, "example.", []*dns.DNSKEY{realKSK, injected}, realKSK, realSigner))
	keys, err := v.fetchAndVerifyDNSKEY("example.", []string{genuine}, trustedDS)
	if err != nil {
		t.Fatalf("expected a DNSKEY RRset signed by the DS-matched key to verify: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected both keys of a genuinely signed RRset to be returned, got %d", len(keys))
	}
}

// TestRootDNSKEYRequiresAnAnchoredKeyToSign is the same property at the
// root, against the configured trust anchors.
func TestRootDNSKEYRequiresAnAnchoredKeyToSign(t *testing.T) {
	rootKSK, rootSigner := genKey(t, ".", true)
	injected, injectedSigner := genKey(t, ".", true)
	ds := rootKSK.ToDS(dns.SHA256)
	v := &Validator{
		Client:  &dns.Client{Timeout: 2 * time.Second},
		Anchors: []TrustAnchor{{KeyTag: ds.KeyTag, Algorithm: ds.Algorithm, DigestType: dns.SHA256, DigestHex: ds.Digest}},
	}

	forged := serveDNSKEYAnswer(t, dnskeySetWithSig(t, ".", []*dns.DNSKEY{rootKSK, injected}, injected, injectedSigner))
	if _, err := v.fetchAndVerifyDNSKEYAtRoot([]string{forged}); err == nil {
		t.Fatalf("expected a root DNSKEY RRset signed only by an injected key to be rejected")
	}
	genuine := serveDNSKEYAnswer(t, dnskeySetWithSig(t, ".", []*dns.DNSKEY{rootKSK, injected}, rootKSK, rootSigner))
	if _, err := v.fetchAndVerifyDNSKEYAtRoot([]string{genuine}); err != nil {
		t.Fatalf("expected a root DNSKEY RRset signed by the anchored key to verify: %v", err)
	}
}

// TestMatchCandidateDSRejectsSHA1: a candidate KSK matched only by a
// SHA-1 DS is not accepted, with its own diagnostic; a SHA-256 or
// SHA-384 DS for the same key is.
func TestMatchCandidateDSRejectsSHA1(t *testing.T) {
	key, _ := genKey(t, "example.org.", true)

	err := matchCandidateDS("example.org.", []*dns.DS{key.ToDS(dns.SHA1)}, key)
	if ce, ok := err.(*ChainError); !ok || ce.Op != "weak-ds-digest" {
		t.Fatalf("expected a weak-ds-digest error for a SHA-1-only match, got %v", err)
	}
	for _, digest := range []uint8{dns.SHA256, dns.SHA384} {
		if err := matchCandidateDS("example.org.", []*dns.DS{key.ToDS(dns.SHA1), key.ToDS(digest)}, key); err != nil {
			t.Fatalf("expected digest type %d to be accepted: %v", digest, err)
		}
	}
	other, _ := genKey(t, "example.org.", true)
	if ce, ok := matchCandidateDS("example.org.", []*dns.DS{other.ToDS(dns.SHA256)}, key).(*ChainError); !ok || ce.Op != "key-mismatch" {
		t.Fatalf("expected key-mismatch for a DS of a different key")
	}
}

// TestLoadTrustAnchors covers the file format the trust_anchor directive
// and sazu-watchd's -trust-anchor flag read.
func TestLoadTrustAnchors(t *testing.T) {
	key, _ := genKey(t, ".", true)
	ds := key.ToDS(dns.SHA256)
	dir := t.TempDir()

	good := filepath.Join(dir, "root.key")
	if err := os.WriteFile(good, []byte("; comment\n"+ds.String()+"\n"+key.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	anchors, err := LoadTrustAnchors(good)
	if err != nil {
		t.Fatalf("LoadTrustAnchors: %v", err)
	}
	if len(anchors) != 2 || !anchors[0].Matches(key) || !anchors[1].Matches(key) {
		t.Fatalf("expected both the DS and the DNSKEY line to anchor the key, got %+v", anchors)
	}

	for name, content := range map[string]string{
		"sha1.key":  key.ToDS(dns.SHA1).String() + "\n",
		"zsk.key":   func() string { z, _ := genKey(t, ".", false); return z.String() + "\n" }(),
		"owner.key": "example. 3600 IN DS " + ds.String()[len(ds.Header().String()):] + "\n",
		"empty.key": "; nothing here\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadTrustAnchors(path); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// TestLoadTrustAnchorsRFC7958: IANA's root-anchors.xml format, keeping
// only KeyDigests valid now with a SHA-256/SHA-384 digest.
func TestLoadTrustAnchorsRFC7958(t *testing.T) {
	const doc = `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="E9724F53-1851-4F86-85E5-F1392102940B" source="http://data.iana.org/root-anchors/root-anchors.xml">
<Zone>.</Zone>
<KeyDigest id="Kjqmt7v" validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
<KeyTag>19036</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5</Digest>
</KeyDigest>
<KeyDigest id="Klajeyz" validFrom="2017-02-02T00:00:00+00:00">
<KeyTag>20326</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
</KeyDigest>
<KeyDigest id="Kmyv6jo" validFrom="2024-07-18T00:00:00+00:00">
<KeyTag>38696</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16</Digest>
<Flags>257</Flags>
</KeyDigest>
</TrustAnchor>`
	path := filepath.Join(t.TempDir(), "root-anchors.xml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	anchors, err := LoadTrustAnchors(path)
	if err != nil {
		t.Fatal(err)
	}
	builtin := RootTrustAnchors()
	if len(anchors) != 2 {
		t.Fatalf("expected the two currently valid anchors, got %+v", anchors)
	}
	for i, a := range anchors {
		if a.KeyTag != builtin[i].KeyTag || !strings.EqualFold(a.DigestHex, builtin[i].DigestHex) {
			t.Fatalf("anchor %d = %+v, want %+v", i, a, builtin[i])
		}
	}
}
