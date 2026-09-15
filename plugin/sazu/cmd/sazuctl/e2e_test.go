package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/sazu"

	"github.com/miekg/dns"
)

// startTestServer boots a real dnsserver.Server, with a fresh sazu.Sazu
// plugin instance installed, listening on UDP and TCP on the same
// ephemeral port -- exactly what a real coredns binary does. Tests in
// this file exercise the actual sazuctl subcommand entry points
// (run* functions, the same code `main` dispatches to for a real
// command-line invocation) against it, end to end over real sockets --
// this is the CLI's own black-box behavior, not just the plugin
// package's internal API (see plugin/sazu/zsk_test.go for that level).
// Chain-of-trust validation is skipped (no real parent zone to publish a
// DS against in a test), matching every other test in this package that
// needs a KSK rollover to succeed.
func startTestServer(t *testing.T) string {
	t.Helper()
	s := &sazu.Sazu{
		Zones:                       []string{"."},
		Store:                       sazu.NewStore(),
		Keys:                        sazu.NewKeyRegistry(),
		Contacts:                    sazu.NewContactRegistry(),
		Validator:                   sazu.NewValidator(),
		Capture:                     sazu.NewRawCapture(5*time.Second, 64),
		InsecureSkipChainValidation: true,
	}
	cfg := &dnsserver.Config{
		Zone:        ".",
		Transport:   "dns",
		ListenHosts: []string{"127.0.0.1"},
		Port:        "0",
	}
	cfg.AddPlugin(func(next plugin.Handler) plugin.Handler {
		s.Next = next
		return s
	})
	cfg.AllowOpcode(dns.OpcodeUpdate)
	cfg.UDPDecorateReaderFunc = s.Capture.DecorateReaderFunc
	cfg.TCPDecorateReaderFunc = s.Capture.DecorateReaderFunc

	srv, err := dnsserver.NewServer("127.0.0.1:0", []*dnsserver.Config{cfg})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Binding UDP first (to learn an available ephemeral port) and then
	// TCP to that exact same port has an inherent, if narrow, TOCTOU
	// race: under load, something else on the machine can grab that TCP
	// port in the gap between the two calls. A handful of retries with a
	// fresh UDP port each time makes that vanishingly unlikely to affect
	// a real test run, at negligible cost on the far more common
	// immediate-success path.
	var pc net.PacketConn
	var l net.Listener
	for attempt := 0; ; attempt++ {
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		_, port, serr := net.SplitHostPort(pc.LocalAddr().String())
		if serr != nil {
			t.Fatalf("SplitHostPort: %v", serr)
		}
		l, err = net.Listen("tcp", "127.0.0.1:"+port)
		if err == nil {
			break
		}
		pc.Close()
		if attempt >= 4 {
			t.Fatalf("Listen (after %d attempts): %v", attempt+1, err)
		}
	}
	t.Cleanup(func() { pc.Close() })
	go func() { _ = srv.ServePacket(pc) }()
	t.Cleanup(func() { l.Close() })
	go func() { _ = srv.Serve(l) }()

	t.Cleanup(func() { _ = srv.Stop() })
	return pc.LocalAddr().String()
}

// queryA queries addr for name's A records over UDP via a real
// dns.Client -- a genuine round trip, the same as any real resolver or
// operator's `dig` would make, to confirm a push's content actually
// became servable rather than just checking the push's own response.
func queryA(t *testing.T, addr, name string) []dns.RR {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	c := new(dns.Client)
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("querying %s: %v", name, err)
	}
	return resp.Answer
}

func writeTestZoneFile(t *testing.T, zone string) string {
	t.Helper()
	return writeZoneFileWithRecords(t, zone, 1, "www."+zone+" 300 IN A 203.0.113.10")
}

// writeZoneFileWithRecords writes a BIND-format zone file for zone with
// the given SOA serial and exactly the record lines given -- every
// content-changing push is a full publish-zone of the zone's complete,
// authoritative content (there is no partial/differential update
// command; see plugin/sazu/README.md's "Considered approaches for
// differential updates"), so a test driving several pushes in sequence
// must pass every record that should still exist at each step, not just
// a newly-added one.
func writeZoneFileWithRecords(t *testing.T, zone string, serial uint32, records ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "zone.txt")
	var buf strings.Builder
	fmt.Fprintf(&buf, "%s 3600 IN SOA ns1.%s hostmaster.%s %d 3600 900 604800 3600\n", zone, zone, zone, serial)
	for _, r := range records {
		buf.WriteString(r)
		buf.WriteString("\n")
	}
	if err := os.WriteFile(path, []byte(buf.String()), 0o644); err != nil {
		t.Fatalf("writing zone file: %v", err)
	}
	return path
}

// TestE2EKSKFullLifecycle exercises the KSK use case end to end through
// the actual sazuctl CLI entry points against a real server: publish-
// trust onboarding (generating a KSK and ZSK together), a full content
// re-push adding a new record, and a full KSK rollover (rotate-key -role
// ksk) -- proving the ZSK it registered still authenticates content
// pushes afterward (a KSK rollover never touches existing ZSKs; see
// KeyRegistry.PinKSK) exactly as a real operator invoking these
// subcommands would experience it.
func TestE2EKSKFullLifecycle(t *testing.T) {
	addr := startTestServer(t)
	zone := "e2e-ksk.example."
	dir := t.TempDir()
	kskPath := filepath.Join(dir, "ksk.private")
	zskPath := filepath.Join(dir, "zsk.private")
	newKSKPath := filepath.Join(dir, "new-ksk.private")

	if err := runPublishTrust([]string{"-zone", zone, "-key", kskPath, "-zsk-key", zskPath, "-target", addr}); err != nil {
		t.Fatalf("publish-trust: %v", err)
	}

	// publish-zone has no -key flag at all -- routine content pushes
	// never need or accept the KSK by construction, only -zsk-key.
	zoneFile := writeTestZoneFile(t, zone)
	if err := runPublishZone([]string{"-zone", zone, "-zsk-key", zskPath, "-zonefile", zoneFile, "-target", addr}); err != nil {
		t.Fatalf("publish-zone (onboarding content): %v", err)
	}
	if answer := queryA(t, addr, "www."+zone); len(answer) != 1 {
		t.Fatalf("expected the onboarded zone to be servable, got %d answers", len(answer))
	}

	withMail := writeZoneFileWithRecords(t, zone, 1,
		"www."+zone+" 300 IN A 203.0.113.10",
		"mail."+zone+" 300 IN A 203.0.113.20",
	)
	if err := runPublishZone([]string{"-zone", zone, "-zsk-key", zskPath, "-zonefile", withMail, "-target", addr}); err != nil {
		t.Fatalf("publish-zone (re-push adding mail): %v", err)
	}
	if answer := queryA(t, addr, "mail."+zone); len(answer) != 1 {
		t.Fatalf("expected the re-pushed content to be servable, got %d answers", len(answer))
	}

	if err := runRotateKey([]string{
		"-zone", zone, "-role", "ksk",
		"-key", kskPath, "-new-key", newKSKPath,
		"-target", addr,
	}); err != nil {
		t.Fatalf("rotate-key -role ksk: %v", err)
	}

	// The ZSK publish-trust registered still authenticates content
	// pushes after the KSK rolls over.
	afterRotation := writeZoneFileWithRecords(t, zone, 1,
		"www."+zone+" 300 IN A 203.0.113.10",
		"mail."+zone+" 300 IN A 203.0.113.20",
		"after-rotation."+zone+" 300 IN A 203.0.113.30",
	)
	if err := runPublishZone([]string{"-zone", zone, "-zsk-key", zskPath, "-zonefile", afterRotation, "-target", addr}); err != nil {
		t.Fatalf("publish-zone after KSK rotation: %v", err)
	}
	if answer := queryA(t, addr, "after-rotation."+zone); len(answer) != 1 {
		t.Fatalf("expected the post-rotation push's content to be servable, got %d answers", len(answer))
	}
}

// TestE2EPushZoneNSEC3FlagServesNSEC3NotNSEC exercises publish-zone's
// -denial-of-existence=nsec3/-nsec3-salt/-nsec3-opt-out flags end to end
// through the actual CLI entry point: proves the flag genuinely changes
// what the server ends up serving (RFC 5155 NSEC3, not plain NSEC), not
// just that runPublishZone accepts it without erroring.
// plugin/sazu/nsec3_test.go already covers RRSIG validity and
// closest-encloser/next-closer proof structure at the plugin-package
// level; this is the CLI's own black-box wiring, mirroring
// startTestServer/queryA's own level for every other flag in this file.
func TestE2EPushZoneNSEC3FlagServesNSEC3NotNSEC(t *testing.T) {
	addr := startTestServer(t)
	zone := "e2e-nsec3.example."
	dir := t.TempDir()
	kskPath := filepath.Join(dir, "ksk.private")
	zskPath := filepath.Join(dir, "zsk.private")
	zoneFile := writeTestZoneFile(t, zone)

	if err := runPublishTrust([]string{"-zone", zone, "-key", kskPath, "-zsk-key", zskPath, "-target", addr}); err != nil {
		t.Fatalf("publish-trust: %v", err)
	}
	if err := runPublishZone([]string{
		"-zone", zone, "-zsk-key", zskPath, "-zonefile", zoneFile,
		"-denial-of-existence", "nsec3", "-nsec3-salt", "AABBCCDD", "-nsec3-opt-out",
		"-target", addr,
	}); err != nil {
		t.Fatalf("publish-zone -nsec3: %v", err)
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("does-not-exist."+zone), dns.TypeA)
	m.SetEdns0(4096, true)
	resp, _, err := new(dns.Client).Exchange(m, addr)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	var sawNSEC3, sawNSEC bool
	for _, rr := range resp.Ns {
		switch v := rr.(type) {
		case *dns.NSEC3:
			sawNSEC3 = true
			if v.Flags != 1 {
				t.Fatalf("NSEC3 Flags = %d, want 1 (-nsec3-opt-out)", v.Flags)
			}
		case *dns.NSEC:
			sawNSEC = true
		}
	}
	if !sawNSEC3 {
		t.Fatalf("expected NSEC3 record(s) in authority, got %+v", resp.Ns)
	}
	if sawNSEC {
		t.Fatalf("expected no plain NSEC records alongside NSEC3, got %+v", resp.Ns)
	}
}

// TestE2EPushZoneDefaultServesNSEC3 proves NSEC3 is what an ordinary
// publish-zone invocation with no NSEC-related flags at all produces --
// -nsec3 defaults to true, so this is the CLI's actual out-of-the-box
// behavior, not just what -nsec3 does when named explicitly (already
// covered above).
func TestE2EPushZoneDefaultServesNSEC3(t *testing.T) {
	addr := startTestServer(t)
	zone := "e2e-nsec3-default.example."
	dir := t.TempDir()
	kskPath := filepath.Join(dir, "ksk.private")
	zskPath := filepath.Join(dir, "zsk.private")
	zoneFile := writeTestZoneFile(t, zone)

	if err := runPublishTrust([]string{"-zone", zone, "-key", kskPath, "-zsk-key", zskPath, "-target", addr}); err != nil {
		t.Fatalf("publish-trust: %v", err)
	}
	if err := runPublishZone([]string{"-zone", zone, "-zsk-key", zskPath, "-zonefile", zoneFile, "-target", addr}); err != nil {
		t.Fatalf("publish-zone (no NSEC-related flags): %v", err)
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("does-not-exist."+zone), dns.TypeA)
	m.SetEdns0(4096, true)
	resp, _, err := new(dns.Client).Exchange(m, addr)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	var sawNSEC3, sawNSEC bool
	for _, rr := range resp.Ns {
		switch rr.(type) {
		case *dns.NSEC3:
			sawNSEC3 = true
		case *dns.NSEC:
			sawNSEC = true
		}
	}
	if !sawNSEC3 {
		t.Fatalf("expected the default publish-zone push to serve NSEC3, got %+v", resp.Ns)
	}
	if sawNSEC {
		t.Fatalf("expected no plain NSEC records alongside the default NSEC3, got %+v", resp.Ns)
	}
}

// TestE2EPushZoneNSEC3FalseFallsBackToPlainNSEC proves
// -denial-of-existence=nsec is a working escape hatch back to plain
// NSEC now that NSEC3 is the default.
func TestE2EPushZoneNSEC3FalseFallsBackToPlainNSEC(t *testing.T) {
	addr := startTestServer(t)
	zone := "e2e-nsec3-fallback.example."
	dir := t.TempDir()
	kskPath := filepath.Join(dir, "ksk.private")
	zskPath := filepath.Join(dir, "zsk.private")
	zoneFile := writeTestZoneFile(t, zone)

	if err := runPublishTrust([]string{"-zone", zone, "-key", kskPath, "-zsk-key", zskPath, "-target", addr}); err != nil {
		t.Fatalf("publish-trust: %v", err)
	}
	if err := runPublishZone([]string{"-zone", zone, "-zsk-key", zskPath, "-zonefile", zoneFile, "-denial-of-existence", "nsec", "-target", addr}); err != nil {
		t.Fatalf("publish-zone -denial-of-existence=nsec: %v", err)
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("does-not-exist."+zone), dns.TypeA)
	m.SetEdns0(4096, true)
	resp, _, err := new(dns.Client).Exchange(m, addr)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	var sawNSEC3, sawNSEC bool
	for _, rr := range resp.Ns {
		switch rr.(type) {
		case *dns.NSEC3:
			sawNSEC3 = true
		case *dns.NSEC:
			sawNSEC = true
		}
	}
	if !sawNSEC {
		t.Fatalf("expected -denial-of-existence nsec to fall back to plain NSEC, got %+v", resp.Ns)
	}
	if sawNSEC3 {
		t.Fatalf("expected no NSEC3 records alongside the plain-NSEC fallback, got %+v", resp.Ns)
	}
}

// TestE2EZSKFullLifecycle exercises the ZSK use case end to end through
// the actual sazuctl CLI entry points: publish-trust onboarding
// (generating a KSK and ZSK together), a routine content push
// authenticated and signed by the ZSK alone (publish-zone never touches
// the KSK at all), retiring that ZSK (retire-zsk) and confirming it no
// longer authenticates anything, then registering a fresh replacement
// (add-zsk) and confirming publish-zone works again with it.
func TestE2EZSKFullLifecycle(t *testing.T) {
	addr := startTestServer(t)
	zone := "e2e-zsk.example."
	dir := t.TempDir()
	kskPath := filepath.Join(dir, "ksk.private")
	zskPath := filepath.Join(dir, "zsk.private")
	newZSKPath := filepath.Join(dir, "new-zsk.private")

	if err := runPublishTrust([]string{"-zone", zone, "-key", kskPath, "-zsk-key", zskPath, "-target", addr}); err != nil {
		t.Fatalf("publish-trust: %v", err)
	}

	// The ZSK authenticates and signs a routine push entirely on its
	// own -- publish-zone never even accepts a KSK.
	zoneFile := writeTestZoneFile(t, zone)
	if err := runPublishZone([]string{"-zone", zone, "-zsk-key", zskPath, "-zonefile", zoneFile, "-target", addr}); err != nil {
		t.Fatalf("publish-zone authenticated by the ZSK: %v", err)
	}
	if answer := queryA(t, addr, "www."+zone); len(answer) != 1 {
		t.Fatalf("expected the ZSK-authenticated push's content to be servable, got %d answers", len(answer))
	}

	if err := runRetireZSK([]string{"-zone", zone, "-ksk-key", kskPath, "-zsk-key", zskPath, "-target", addr}); err != nil {
		t.Fatalf("retire-zsk: %v", err)
	}

	// The retired ZSK no longer authenticates anything.
	withAfterRetirement := writeZoneFileWithRecords(t, zone, 1,
		"www."+zone+" 300 IN A 203.0.113.10",
		"after-retirement."+zone+" 300 IN A 198.51.100.2",
	)
	if err := runPublishZone([]string{"-zone", zone, "-zsk-key", zskPath, "-zonefile", withAfterRetirement, "-target", addr}); err == nil {
		t.Fatalf("expected a push authenticated by a retired ZSK to be rejected")
	}

	// A freshly registered ZSK works again.
	if err := runAddZSK([]string{"-zone", zone, "-ksk-key", kskPath, "-zsk-key", newZSKPath, "-target", addr}); err != nil {
		t.Fatalf("add-zsk (replacement): %v", err)
	}
	stillFine := writeZoneFileWithRecords(t, zone, 1,
		"www."+zone+" 300 IN A 203.0.113.10",
		"still-fine."+zone+" 300 IN A 203.0.113.60",
	)
	if err := runPublishZone([]string{"-zone", zone, "-zsk-key", newZSKPath, "-zonefile", stillFine, "-target", addr}); err != nil {
		t.Fatalf("publish-zone with the replacement ZSK: %v", err)
	}
	if answer := queryA(t, addr, "still-fine."+zone); len(answer) != 1 {
		t.Fatalf("expected the replacement ZSK's push to be servable, got %d answers", len(answer))
	}
}

// TestE2ERotateKeyZSKRoleRegistersThenRetires proves rotate-key's -role
// zsk convenience path -- register a new ZSK, retire the old one -- end
// to end: the old ZSK stops authenticating and the new one does, with a
// single command instead of separate add-zsk/retire-zsk calls.
func TestE2ERotateKeyZSKRoleRegistersThenRetires(t *testing.T) {
	addr := startTestServer(t)
	zone := "e2e-rotate-zsk.example."
	dir := t.TempDir()
	kskPath := filepath.Join(dir, "ksk.private")
	oldZSKPath := filepath.Join(dir, "old-zsk.private")
	newZSKPath := filepath.Join(dir, "new-zsk.private")

	if err := runPublishTrust([]string{"-zone", zone, "-key", kskPath, "-zsk-key", oldZSKPath, "-target", addr}); err != nil {
		t.Fatalf("publish-trust: %v", err)
	}
	zoneFile := writeTestZoneFile(t, zone)
	if err := runPublishZone([]string{"-zone", zone, "-zsk-key", oldZSKPath, "-zonefile", zoneFile, "-target", addr}); err != nil {
		t.Fatalf("publish-zone (onboarding content): %v", err)
	}

	if err := runRotateKey([]string{
		"-zone", zone, "-role", "zsk",
		"-key", kskPath, "-current-zsk-key", oldZSKPath, "-new-zsk-key", newZSKPath,
		"-target", addr,
	}); err != nil {
		t.Fatalf("rotate-key -role zsk: %v", err)
	}

	shouldFail := writeZoneFileWithRecords(t, zone, 1,
		"www."+zone+" 300 IN A 203.0.113.10",
		"should-fail."+zone+" 300 IN A 198.51.100.3",
	)
	if err := runPublishZone([]string{"-zone", zone, "-zsk-key", oldZSKPath, "-zonefile", shouldFail, "-target", addr}); err == nil {
		t.Fatalf("expected the old ZSK to no longer authenticate after rotate-key -role zsk")
	}

	shouldSucceed := writeZoneFileWithRecords(t, zone, 1,
		"www."+zone+" 300 IN A 203.0.113.10",
		"should-succeed."+zone+" 300 IN A 203.0.113.70",
	)
	if err := runPublishZone([]string{"-zone", zone, "-zsk-key", newZSKPath, "-zonefile", shouldSucceed, "-target", addr}); err != nil {
		t.Fatalf("publish-zone with the new ZSK after rotation: %v", err)
	}
	if answer := queryA(t, addr, "should-succeed."+zone); len(answer) != 1 {
		t.Fatalf("expected the new ZSK's push to be servable, got %d answers", len(answer))
	}
}

// TestE2EInitZoneThenPublishZoneWithYAML exercises the "how do I even get
// a zone file to push" onboarding path end to end: init-zone writes a
// starter YAML zone definition, and publish-zone accepts it directly as
// -zonefile (no separate conversion step) -- proving the YAML front end
// (zoneyaml.go) produces real, servable zone content through the actual
// CLI commands a customer would run.
func TestE2EInitZoneThenPublishZoneWithYAML(t *testing.T) {
	addr := startTestServer(t)
	zone := "e2e-yaml-zone.example."
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "zone.yaml")
	kskPath := filepath.Join(dir, "ksk.private")
	zskPath := filepath.Join(dir, "zsk.private")

	if err := runInitZone([]string{"-zone", zone, "-out", yamlPath}); err != nil {
		t.Fatalf("init-zone: %v", err)
	}
	if _, err := os.Stat(yamlPath); err != nil {
		t.Fatalf("expected init-zone to create %s: %v", yamlPath, err)
	}

	if err := runPublishTrust([]string{"-zone", zone, "-key", kskPath, "-zsk-key", zskPath, "-target", addr}); err != nil {
		t.Fatalf("publish-trust: %v", err)
	}
	if err := runPublishZone([]string{"-zone", zone, "-zsk-key", zskPath, "-zonefile", yamlPath, "-target", addr}); err != nil {
		t.Fatalf("publish-zone with a YAML zonefile: %v", err)
	}

	// The starter template's own example records (www and mail) should
	// be exactly what got onboarded.
	if answer := queryA(t, addr, "www."+zone); len(answer) != 1 {
		t.Fatalf("expected the YAML template's www record to be servable, got %d answers", len(answer))
	}
	if answer := queryA(t, addr, "mail."+zone); len(answer) != 1 {
		t.Fatalf("expected the YAML template's mail record to be servable, got %d answers", len(answer))
	}
}

// TestE2EInitZoneRefusesToOverwriteExistingFile proves init-zone
// doesn't silently clobber a file a customer may have already started
// editing.
func TestE2EInitZoneRefusesToOverwriteExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.yaml")
	if err := os.WriteFile(path, []byte("not a zone definition"), 0o644); err != nil {
		t.Fatalf("writing pre-existing file: %v", err)
	}
	if err := runInitZone([]string{"-zone", "example.org.", "-out", path}); err == nil {
		t.Fatalf("expected init-zone to refuse overwriting an existing file")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "not a zone definition" {
		t.Fatalf("expected the existing file to survive untouched, got %q err=%v", data, err)
	}
}

// TestE2EZoneConvertProducesAPushableZoneFile proves zone-convert's
// output isn't just plausible-looking text -- publish-zone can load and
// push the exact BIND-format file it produces from a YAML source.
func TestE2EZoneConvertProducesAPushableZoneFile(t *testing.T) {
	addr := startTestServer(t)
	zone := "e2e-zone-convert.example."
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "zone.yaml")
	zonePath := filepath.Join(dir, "zone.zone")
	kskPath := filepath.Join(dir, "ksk.private")
	zskPath := filepath.Join(dir, "zsk.private")

	if err := runInitZone([]string{"-zone", zone, "-out", yamlPath}); err != nil {
		t.Fatalf("init-zone: %v", err)
	}
	if err := runZoneConvert([]string{"-in", yamlPath, "-out", zonePath}); err != nil {
		t.Fatalf("zone-convert: %v", err)
	}

	if err := runPublishTrust([]string{"-zone", zone, "-key", kskPath, "-zsk-key", zskPath, "-target", addr}); err != nil {
		t.Fatalf("publish-trust: %v", err)
	}
	if err := runPublishZone([]string{"-zone", zone, "-zsk-key", zskPath, "-zonefile", zonePath, "-target", addr}); err != nil {
		t.Fatalf("publish-zone with the converted BIND zone file: %v", err)
	}
	if answer := queryA(t, addr, "www."+zone); len(answer) != 1 {
		t.Fatalf("expected the converted zone file's www record to be servable, got %d answers", len(answer))
	}
}
