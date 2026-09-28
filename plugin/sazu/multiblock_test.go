package sazu

import (
	"net"
	"testing"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/miekg/dns"
)

// TestTwoServerBlocksOnOneListener: two sazu server blocks sharing a
// listener each receive their own pushes' raw bytes.
func TestTwoServerBlocksOnOneListener(t *testing.T) {
	var configs []*dnsserver.Config
	for _, zone := range []string{"example.org.", "example.net."} {
		s := newTestSazu(zone)
		cfg := &dnsserver.Config{Zone: zone, Transport: "dns", ListenHosts: []string{"127.0.0.1"}, Port: "0"}
		cfg.AddPlugin(func(next plugin.Handler) plugin.Handler { s.Next = next; return s })
		cfg.AllowOpcode(dns.OpcodeUpdate)
		cfg.CaptureRawRequests(dns.OpcodeUpdate)
		configs = append(configs, cfg)
	}
	srv, err := dnsserver.NewServer("127.0.0.1:0", configs)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	defer srv.Stop()

	for _, zone := range []string{"example.org.", "example.net."} {
		key, priv, err := GenerateEd25519Key(zone, true)
		if err != nil {
			t.Fatal(err)
		}
		soa := &dns.SOA{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns: "ns." + zone, Mbox: "hostmaster." + zone, Serial: 1, Minttl: 300}
		m, err := BuildFullZonePush(zone, soa, nil, key, priv, nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp := sendRaw(t, l.Addr().String(), signNow(t, m, key, priv)); resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("%s: onboarding rcode = %s, want NOERROR", zone, dns.RcodeToString[resp.Rcode])
		}
	}
}
