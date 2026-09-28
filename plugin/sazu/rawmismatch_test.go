package sazu

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/coredns/coredns/core/dnsserver"

	"github.com/miekg/dns"
)

// TestForgedMessagePairedWithCapturedSignedBytesIsRefused: the server
// applies only the message whose bytes SIG(0) verified. An attacker who
// spoofs the victim's source address and message ID pairs an unsigned
// decommission (carrying a copy of the victim's SIG(0) record) with the
// victim's genuinely KSK-signed bytes. Only what the signature covers
// may be applied: the zone must survive.
func TestForgedMessagePairedWithCapturedSignedBytesIsRefused(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	ksk, kskPriv, _, _ := onboardKSKAndZSK(t, addr)

	op, err := BuildContactOp("example.org.", []string{"mailto:owner@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	legit := new(dns.Msg)
	legit.SetQuestion("example.org.", dns.TypeSOA)
	legit.Opcode = dns.OpcodeUpdate
	legit.Id = 4242
	legit.Insert([]dns.RR{op})
	now := time.Now()
	legitWire, err := SignUpdate(legit, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	legitParsed := new(dns.Msg)
	if err := legitParsed.Unpack(legitWire); err != nil {
		t.Fatal(err)
	}

	forged := BuildDecommissionPush("example.org.")
	forged.Id = legit.Id
	forged.Extra = append(forged.Extra, legitParsed.Extra[len(legitParsed.Extra)-1])
	forgedWire, err := forged.Pack()
	if err != nil {
		t.Fatal(err)
	}
	forgedParsed := new(dns.Msg)
	if err := forgedParsed.Unpack(forgedWire); err != nil {
		t.Fatal(err)
	}

	// The core hands the plugin the bytes it correlated with this request
	// (source address and message ID); a spoofed packet can make those
	// the victim's while the parsed message is the attacker's.
	src := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5353}
	ctx := context.WithValue(context.Background(), dnsserver.RawRequestKey{}, legitWire)
	w := &recordingResponseWriter{addr: src}
	s.ServeDNS(ctx, w, forgedParsed)

	// Only the signed bytes count: the genuine contact update is what
	// gets applied, and the forged decommission riding next to it is
	// ignored entirely.
	if _, pinned := s.Keys.Get("example.org."); !pinned {
		t.Fatalf("the forged decommission was applied: the zone is gone")
	}
	if addrs, _ := s.Contacts.Get("example.org."); len(addrs) != 1 || addrs[0] != "mailto:owner@example.org" {
		t.Fatalf("expected the genuinely signed contact update to be what was applied, contact is %v", addrs)
	}
}
