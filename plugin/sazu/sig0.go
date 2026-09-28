package sazu

import (
	"crypto/ed25519"
	"time"

	"github.com/miekg/dns"
)

// SignUpdate signs m (an RFC 2136 UPDATE message, question section set,
// no SIG(0) yet) with priv, acting as signerKey, and returns the exact
// wire bytes to send: SIG.Sign packs the message, appends the SIG(0)
// record last in the additional section and fixes up the header count
// (RFC 2931 §3.1). RFC 2931 signs literal wire bytes, so the returned
// bytes must be sent as they are. An OPT record is added first if m has
// none, so the server can report its status as an RFC 8914 Extended DNS
// Error (EDNS(0), RFC 6891).
func SignUpdate(m *dns.Msg, signerKey *dns.DNSKEY, priv ed25519.PrivateKey, inception, expiration time.Time) ([]byte, error) {
	sig := &dns.SIG{
		RRSIG: dns.RRSIG{
			Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeSIG, Class: dns.ClassANY, Ttl: 0},
			Algorithm:  signerKey.Algorithm,
			KeyTag:     signerKey.KeyTag(),
			SignerName: signerKey.Hdr.Name,
			Inception:  uint32(inception.Unix()),
			Expiration: uint32(expiration.Unix()),
		},
	}
	if m.IsEdns0() == nil {
		m.SetEdns0(dns.DefaultMsgSize, false)
	}
	return sig.Sign(priv, m)
}

// VerifySIG0 verifies a SIG(0)-signed message's raw wire bytes (as
// received, not re-packed -- see SignUpdate's doc comment for why that
// distinction matters) against candidateKey. It also checks the
// signature's validity window, which SIG.Verify itself already enforces
// internally (unlike RRSIG.Verify, whose caller must check it separately).
func VerifySIG0(raw []byte, candidateKey *dns.DNSKEY) error {
	m := new(dns.Msg)
	if err := m.Unpack(raw); err != nil {
		return err
	}
	sigRR := isSig0(m)
	if sigRR == nil {
		return chainErr("sig0", "message has no trailing SIG(0) record")
	}
	key := &dns.KEY{DNSKEY: *candidateKey}
	return sigRR.Verify(key, raw)
}

// isSig0 checks whether m's last additional-section record is a SIG(0)
// transaction signature (a SIG RR with TypeCovered 0, RFC 2931 §3), the
// same way Msg.IsTsig checks for a trailing TSIG.
func isSig0(m *dns.Msg) *dns.SIG {
	if len(m.Extra) == 0 {
		return nil
	}
	last := m.Extra[len(m.Extra)-1]
	sig, ok := last.(*dns.SIG)
	if !ok || sig.Header().Rrtype != dns.TypeSIG || sig.TypeCovered != 0 {
		return nil
	}
	return sig
}
