package test

import (
	"crypto/ed25519"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/sazu"

	"github.com/miekg/dns"
)

// freeUDPPort returns a port that was free a moment ago, for a server whose
// address another server's configuration has to name.
func freeUDPPort(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port)
}

func sazuPush(t *testing.T, addr string, m *dns.Msg, key *dns.DNSKEY, priv ed25519.PrivateKey) *dns.Msg {
	t.Helper()
	now := time.Now()
	wire, err := sazu.SignUpdate(m, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	co, err := dns.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer co.Close()
	if _, err := co.Write(wire); err != nil {
		t.Fatal(err)
	}
	resp, err := co.ReadMsg()
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestSazuPrimaryWithSecondary: a SAZU zone is served by an ordinary
// CoreDNS secondary. The secondary transfers it (transfer plugin), is sent
// NOTIFY after the next push, and serves the owner's NSEC3 proofs.
func TestSazuPrimaryWithSecondary(t *testing.T) {
	const zone = "example.org."
	secPort := freeUDPPort(t)

	primary, _, primaryTCP, err := CoreDNSServerAndPorts(`example.org:0 {
		bind 127.0.0.1
		sazu {
			insecure_skip_chain_validation
		}
		transfer {
			to 127.0.0.1:` + secPort + `
		}
	}`)
	if err != nil {
		t.Fatalf("Could not start the SAZU primary: %s", err)
	}
	defer primary.Stop()

	key, priv, err := sazu.GenerateEd25519Key(zone, true)
	if err != nil {
		t.Fatal(err)
	}
	push := func(serial uint32, names ...string) {
		t.Helper()
		soa := &dns.SOA{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns: "ns1." + zone, Mbox: "hostmaster." + zone, Serial: serial, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300}
		rrs := []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns1." + zone}}
		for _, n := range names {
			rrs = append(rrs, &dns.A{Hdr: dns.RR_Header{Name: n + "." + zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 1)})
		}
		m, err := sazu.BuildFullZonePushNSEC3(zone, soa, rrs, key, priv, nil, sazu.NSEC3Options{})
		if err != nil {
			t.Fatal(err)
		}
		// The push carries the DNSKEY RRset, so it is a control change:
		// it names the zone's version, which each push increments.
		m.Answer = append(m.Answer, sazu.BuildVersionPrereq(zone, uint64(serial-1)))
		if resp := sazuPush(t, primaryTCP, m, key, priv); resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("push of serial %d: rcode %s", serial, dns.RcodeToString[resp.Rcode])
		}
	}
	push(1, "www")

	secondary, err := CoreDNSServer(`example.org:` + secPort + ` {
		bind 127.0.0.1
		secondary {
			transfer from ` + primaryTCP + `
		}
	}`)
	if err != nil {
		t.Fatalf("Could not start the secondary: %s", err)
	}
	defer secondary.Stop()
	secUDP := "127.0.0.1:" + secPort

	waitFor := func(name string) *dns.Msg {
		t.Helper()
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		m.SetEdns0(4096, true)
		for range 200 {
			if r, err := dns.Exchange(m, secUDP); err == nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
				return r
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("the secondary never served %s", name)
		return nil
	}
	waitFor("www." + zone)

	// The owner's NSEC3 proofs reach resolvers through the secondary.
	m := new(dns.Msg)
	m.SetQuestion("nope."+zone, dns.TypeA)
	m.SetEdns0(4096, true)
	r, err := dns.Exchange(m, secUDP)
	if err != nil {
		t.Fatal(err)
	}
	nsec3 := 0
	for _, rr := range r.Ns {
		if rr.Header().Rrtype == dns.TypeNSEC3 {
			nsec3++
		}
	}
	if r.Rcode != dns.RcodeNameError || nsec3 == 0 {
		t.Fatalf("expected NXDOMAIN with NSEC3 proofs from the secondary, got %s with %d NSEC3", dns.RcodeToString[r.Rcode], nsec3)
	}

	// The next push is sent to the secondary by NOTIFY. It queues behind
	// the NOTIFY for the first push, which the secondary, not yet running,
	// never answered: the transfer plugin retries for a few seconds.
	push(2, "www", "mail")
	waitFor("mail." + zone)
}
