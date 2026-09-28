package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestEmailToMboxConvertsOrdinaryAddress(t *testing.T) {
	got, err := emailToMbox("hostmaster@example.org")
	if err != nil {
		t.Fatalf("emailToMbox: %v", err)
	}
	if want := "hostmaster.example.org."; got != want {
		t.Fatalf("emailToMbox(hostmaster@example.org) = %q, want %q", got, want)
	}
}

func TestEmailToMboxEscapesLiteralDotsInLocalPart(t *testing.T) {
	got, err := emailToMbox("john.doe@example.org")
	if err != nil {
		t.Fatalf("emailToMbox: %v", err)
	}
	if want := `john\.doe.example.org.`; got != want {
		t.Fatalf("emailToMbox(john.doe@example.org) = %q, want %q", got, want)
	}
}

func TestEmailToMboxRejectsAddressWithoutAt(t *testing.T) {
	if _, err := emailToMbox("not-an-email"); err == nil {
		t.Fatalf("expected an error for an address with no @")
	}
}

func TestResolveSerialAutoIsTodayAsYYYYMMDD00(t *testing.T) {
	got, err := resolveSerial("auto")
	if err != nil {
		t.Fatalf("resolveSerial(auto): %v", err)
	}
	want := dateSerial(time.Now().UTC())
	if got != want {
		t.Fatalf("resolveSerial(auto) = %d, want %d", got, want)
	}
}

func TestResolveSerialEmptyIsAlsoAuto(t *testing.T) {
	got, err := resolveSerial("")
	if err != nil {
		t.Fatalf("resolveSerial(\"\"): %v", err)
	}
	want := dateSerial(time.Now().UTC())
	if got != want {
		t.Fatalf("resolveSerial(\"\") = %d, want %d", got, want)
	}
}

func TestResolveSerialAcceptsExplicitNumber(t *testing.T) {
	got, err := resolveSerial("2026091501")
	if err != nil {
		t.Fatalf("resolveSerial: %v", err)
	}
	if got != 2026091501 {
		t.Fatalf("resolveSerial(2026091501) = %d, want 2026091501", got)
	}
}

func TestResolveSerialRejectsGarbage(t *testing.T) {
	if _, err := resolveSerial("not-a-number"); err == nil {
		t.Fatalf("expected an error for a non-numeric, non-auto serial")
	}
}

func TestDateSerialFormat(t *testing.T) {
	got := dateSerial(time.Date(2026, time.March, 5, 0, 0, 0, 0, time.UTC))
	if want := uint32(2026030500); got != want {
		t.Fatalf("dateSerial(2026-03-05) = %d, want %d", got, want)
	}
}

func TestRecordOwnerNameResolvesApexRelativeAndAbsolute(t *testing.T) {
	const zone = "example.org."
	cases := map[string]string{
		"@":                  zone,
		"":                   zone,
		"www":                "www.example.org.",
		"other.example.org.": "other.example.org.",
	}
	for in, want := range cases {
		if got := recordOwnerName(in, zone); got != want {
			t.Fatalf("recordOwnerName(%q, %q) = %q, want %q", in, zone, got, want)
		}
	}
}

func TestYamlZoneToRRsBuildsSOAAndRecords(t *testing.T) {
	yz := &yamlZoneFile{
		Zone: "example.org.",
		TTL:  600,
		SOA: yamlSOA{
			NS:         "ns1.example.org.",
			AdminEmail: "hostmaster@example.org",
			Serial:     "2026091500",
			Refresh:    3600, Retry: 900, Expire: 604800, MinTTL: 300,
		},
		Records: []yamlRecord{
			{Name: "www", Type: "A", Value: "203.0.113.10"},
			{Name: "@", Type: "MX", Value: "10 mail.example.org."},
			{Name: "custom", Type: "A", Value: "203.0.113.99", TTL: 60},
		},
	}
	soa, rrs, err := yamlZoneToRRs(yz, "")
	if err != nil {
		t.Fatalf("yamlZoneToRRs: %v", err)
	}
	if soa.Serial != 2026091500 {
		t.Fatalf("soa.Serial = %d, want 2026091500", soa.Serial)
	}
	if soa.Mbox != "hostmaster.example.org." {
		t.Fatalf("soa.Mbox = %q, want hostmaster.example.org.", soa.Mbox)
	}
	if soa.Hdr.Ttl != 600 {
		t.Fatalf("soa Hdr.Ttl = %d, want 600 (the zone's default ttl)", soa.Hdr.Ttl)
	}
	if len(rrs) != 3 {
		t.Fatalf("expected 3 records, got %d: %+v", len(rrs), rrs)
	}
	www, ok := rrs[0].(*dns.A)
	if !ok || www.Hdr.Name != "www.example.org." || !www.A.Equal(net.IPv4(203, 0, 113, 10)) || www.Hdr.Ttl != 600 {
		t.Fatalf("unexpected first record: %+v", rrs[0])
	}
	mx, ok := rrs[1].(*dns.MX)
	if !ok || mx.Hdr.Name != "example.org." || mx.Preference != 10 || mx.Mx != "mail.example.org." {
		t.Fatalf("unexpected second record: %+v", rrs[1])
	}
	custom, ok := rrs[2].(*dns.A)
	if !ok || custom.Hdr.Ttl != 60 {
		t.Fatalf("expected the third record's own ttl (60) to override the zone default, got %+v", rrs[2])
	}
}

func TestYamlZoneToRRsRejectsMissingAdminEmailOrMbox(t *testing.T) {
	yz := &yamlZoneFile{Zone: "example.org.", SOA: yamlSOA{NS: "ns1.example.org."}}
	if _, _, err := yamlZoneToRRs(yz, ""); err == nil {
		t.Fatalf("expected an error when neither soa.admin_email nor soa.mbox is given")
	}
}

func TestYamlZoneToRRsRejectsMissingNS(t *testing.T) {
	yz := &yamlZoneFile{Zone: "example.org.", SOA: yamlSOA{AdminEmail: "hostmaster@example.org"}}
	if _, _, err := yamlZoneToRRs(yz, ""); err == nil {
		t.Fatalf("expected an error when soa.ns is missing")
	}
}

func TestYamlZoneToRRsFallsBackToGivenZoneWhenFileOmitsIt(t *testing.T) {
	yz := &yamlZoneFile{
		SOA: yamlSOA{NS: "ns1.example.org.", AdminEmail: "hostmaster@example.org", Serial: "2026010100"},
	}
	soa, _, err := yamlZoneToRRs(yz, "example.org.")
	if err != nil {
		t.Fatalf("yamlZoneToRRs: %v", err)
	}
	if soa.Hdr.Name != "example.org." {
		t.Fatalf("expected the fallback zone to be used, got owner %q", soa.Hdr.Name)
	}
}

func TestYamlZoneToRRsRejectsRecordWithoutTypeOrValue(t *testing.T) {
	yz := &yamlZoneFile{
		Zone: "example.org.",
		SOA:  yamlSOA{NS: "ns1.example.org.", AdminEmail: "hostmaster@example.org"},
		Records: []yamlRecord{
			{Name: "www", Type: "A"},
		},
	}
	if _, _, err := yamlZoneToRRs(yz, ""); err == nil {
		t.Fatalf("expected an error for a record with no value")
	}
}

func TestLoadYAMLZoneRoundTripsThroughAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zone.yaml")
	content := `
zone: example.org.
ttl: 300
soa:
  ns: ns1.example.org.
  admin_email: hostmaster@example.org
  serial: "2026091500"
records:
  - name: www
    type: A
    value: 203.0.113.10
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing test YAML: %v", err)
	}
	soa, rrs, err := loadYAMLZone(path, "")
	if err != nil {
		t.Fatalf("loadYAMLZone: %v", err)
	}
	if soa.Serial != 2026091500 || len(rrs) != 1 {
		t.Fatalf("unexpected result: soa=%+v rrs=%+v", soa, rrs)
	}
}

func TestLoadZoneSourceDispatchesOnExtension(t *testing.T) {
	dir := t.TempDir()

	yamlPath := filepath.Join(dir, "zone.yaml")
	yamlContent := "zone: example.org.\nsoa:\n  ns: ns1.example.org.\n  admin_email: hostmaster@example.org\n  serial: \"1\"\n"
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("writing YAML: %v", err)
	}
	if soa, _, err := loadZoneSource(yamlPath, ""); err != nil || soa.Serial != 1 {
		t.Fatalf("loadZoneSource(.yaml) = soa=%+v err=%v, want serial 1, no error", soa, err)
	}

	zonePath := filepath.Join(dir, "zone.zone")
	zoneContent := "example.org. 3600 IN SOA ns1.example.org. hostmaster.example.org. 2 3600 900 604800 3600\n"
	if err := os.WriteFile(zonePath, []byte(zoneContent), 0o644); err != nil {
		t.Fatalf("writing zone file: %v", err)
	}
	if soa, _, err := loadZoneSource(zonePath, "example.org."); err != nil || soa.Serial != 2 {
		t.Fatalf("loadZoneSource(.zone) = soa=%+v err=%v, want serial 2, no error", soa, err)
	}
}
