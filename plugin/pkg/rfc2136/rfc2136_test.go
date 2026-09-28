package rfc2136

import (
	"testing"

	"github.com/miekg/dns"
)

type fakeZone map[string][]dns.RR // name -> RRs

func (z fakeZone) NameInUse(name string) bool { return len(z[CanonicalName(name)]) > 0 }

func (z fakeZone) RRset(name string, rrtype uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range z[CanonicalName(name)] {
		if rr.Header().Rrtype == rrtype {
			out = append(out, rr)
		}
	}
	return out
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

// wire returns rr as it arrives on the wire, with Rdlength set.
func wire(t *testing.T, rr dns.RR) dns.RR {
	t.Helper()
	buf := make([]byte, 512)
	n, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := dns.UnpackRR(buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSerialGreater(t *testing.T) {
	for _, c := range []struct {
		a, b uint32
		want bool
	}{
		{2, 1, true},
		{1, 1, false},
		{1, 2, false},
		{0, 0xFFFFFFFF, true}, // wraps around
		{0xFFFFFFFF, 0, false},
		{1 << 31, 0, false}, // the undefined half-space
	} {
		if got := SerialGreater(c.a, c.b); got != c.want {
			t.Errorf("SerialGreater(%d, %d) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestCheckPrerequisites(t *testing.T) {
	a1 := mustRR(t, "www.example.org. 300 IN A 192.0.2.1")
	a2 := mustRR(t, "www.example.org. 300 IN A 192.0.2.2")
	z := fakeZone{"www.example.org.": {a1, a2}}

	prereq := func(name string, class, rrtype uint16) dns.RR {
		return wire(t, &dns.ANY{Hdr: dns.RR_Header{Name: name, Rrtype: rrtype, Class: class}})
	}
	valueDep := func(rr dns.RR) dns.RR {
		rr = dns.Copy(rr)
		rr.Header().Ttl = 0
		return wire(t, rr)
	}
	for _, c := range []struct {
		name    string
		prereqs []dns.RR
		want    int
	}{
		{"name in use", []dns.RR{prereq("www.example.org.", dns.ClassANY, dns.TypeANY)}, dns.RcodeSuccess},
		{"name not in use", []dns.RR{prereq("nope.example.org.", dns.ClassANY, dns.TypeANY)}, dns.RcodeNameError},
		{"name must not be in use", []dns.RR{prereq("www.example.org.", dns.ClassNONE, dns.TypeANY)}, dns.RcodeYXDomain},
		{"rrset exists", []dns.RR{prereq("www.example.org.", dns.ClassANY, dns.TypeA)}, dns.RcodeSuccess},
		{"rrset missing", []dns.RR{prereq("www.example.org.", dns.ClassANY, dns.TypeMX)}, dns.RcodeNXRrset},
		{"rrset must not exist", []dns.RR{prereq("www.example.org.", dns.ClassNONE, dns.TypeA)}, dns.RcodeYXRrset},
		{"whole rrset matches", []dns.RR{valueDep(a1), valueDep(a2)}, dns.RcodeSuccess},
		// §2.4.2: the RRset must match exactly, not just contain the RRs.
		{"part of the rrset", []dns.RR{valueDep(a1)}, dns.RcodeNXRrset},
		{"nonzero TTL", []dns.RR{a1}, dns.RcodeFormatError},
		{"out of zone", []dns.RR{prereq("www.example.net.", dns.ClassANY, dns.TypeANY)}, dns.RcodeNotZone},
	} {
		if got, _ := CheckPrerequisites("example.org.", c.prereqs, dns.ClassINET, z, nil); got != c.want {
			t.Errorf("%s: rcode %s, want %s", c.name, dns.RcodeToString[got], dns.RcodeToString[c.want])
		}
	}
}

func TestPrescanUpdates(t *testing.T) {
	add := mustRR(t, "www.example.org. 300 IN A 192.0.2.1")
	del := wire(t, &dns.ANY{Hdr: dns.RR_Header{Name: "www.example.org.", Rrtype: dns.TypeA, Class: dns.ClassANY}})
	for _, c := range []struct {
		name    string
		updates []dns.RR
		want    int
	}{
		{"add and delete", []dns.RR{add, del}, dns.RcodeSuccess},
		{"out of zone", []dns.RR{mustRR(t, "www.example.net. 300 IN A 192.0.2.1")}, dns.RcodeNotZone},
		{"meta type add", []dns.RR{wire(t, &dns.ANY{Hdr: dns.RR_Header{Name: "www.example.org.", Rrtype: dns.TypeANY, Class: dns.ClassINET, Ttl: 300}})}, dns.RcodeFormatError},
		{"delete with a TTL", []dns.RR{wire(t, &dns.ANY{Hdr: dns.RR_Header{Name: "www.example.org.", Rrtype: dns.TypeA, Class: dns.ClassANY, Ttl: 60}})}, dns.RcodeFormatError},
	} {
		if got, _ := PrescanUpdates("example.org.", c.updates, dns.ClassINET, nil); got != c.want {
			t.Errorf("%s: rcode %s, want %s", c.name, dns.RcodeToString[got], dns.RcodeToString[c.want])
		}
	}
	policy := func(dns.RR) int { return dns.RcodeNotImplemented }
	if got, _ := PrescanUpdates("example.org.", []dns.RR{add}, dns.ClassINET, policy); got != dns.RcodeNotImplemented {
		t.Errorf("the policy's RCODE must be returned, got %s", dns.RcodeToString[got])
	}
}
