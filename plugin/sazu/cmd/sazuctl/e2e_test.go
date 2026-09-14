package main

import (
	"net"
	"os"
	"path/filepath"
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
	path := filepath.Join(t.TempDir(), "zone.txt")
	content := zone + " 3600 IN SOA ns1." + zone + " hostmaster." + zone + " 1 3600 900 604800 3600\n" +
		"www." + zone + " 300 IN A 203.0.113.10\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing zone file: %v", err)
	}
	return path
}

// TestE2EKSKFullLifecycle exercises the KSK use case end to end through
// the actual sazuctl CLI entry points against a real server: onboarding
// (push-zone), an ordinary differential push (push-update), and a full
// KSK rollover (rotate-key -role ksk) -- proving the old key stops
// authenticating and the new one takes over, exactly as a real operator
// invoking these subcommands would experience it.
func TestE2EKSKFullLifecycle(t *testing.T) {
	addr := startTestServer(t)
	zone := "e2e-ksk.example."
	dir := t.TempDir()
	kskPath := filepath.Join(dir, "ksk.private")
	newKSKPath := filepath.Join(dir, "new-ksk.private")

	zoneFile := writeTestZoneFile(t, zone)
	if err := runPushZone([]string{"-zone", zone, "-key", kskPath, "-zonefile", zoneFile, "-target", addr}); err != nil {
		t.Fatalf("push-zone (onboarding): %v", err)
	}
	if answer := queryA(t, addr, "www."+zone); len(answer) != 1 {
		t.Fatalf("expected the onboarded zone to be servable, got %d answers", len(answer))
	}

	if err := runPushUpdate([]string{
		"-zone", zone, "-key", kskPath,
		"-add", "mail." + zone + " 300 IN A 203.0.113.20",
		"-target", addr,
	}); err != nil {
		t.Fatalf("push-update: %v", err)
	}
	if answer := queryA(t, addr, "mail."+zone); len(answer) != 1 {
		t.Fatalf("expected the differential push's content to be servable, got %d answers", len(answer))
	}

	if err := runRotateKey([]string{
		"-zone", zone, "-role", "ksk",
		"-key", kskPath, "-new-key", newKSKPath,
		"-target", addr,
	}); err != nil {
		t.Fatalf("rotate-key -role ksk: %v", err)
	}

	// The old KSK no longer authenticates anything for this zone.
	if err := runPushUpdate([]string{
		"-zone", zone, "-key", kskPath,
		"-add", "evil." + zone + " 300 IN A 198.51.100.1",
		"-target", addr,
	}); err == nil {
		t.Fatalf("expected a push signed by the superseded KSK to be rejected after rotation")
	}

	// The new KSK does.
	if err := runPushUpdate([]string{
		"-zone", zone, "-key", newKSKPath,
		"-add", "after-rotation." + zone + " 300 IN A 203.0.113.30",
		"-target", addr,
	}); err != nil {
		t.Fatalf("push-update with the new KSK after rotation: %v", err)
	}
	if answer := queryA(t, addr, "after-rotation."+zone); len(answer) != 1 {
		t.Fatalf("expected the post-rotation push's content to be servable, got %d answers", len(answer))
	}
}

// TestE2EZSKFullLifecycle exercises the ZSK use case end to end through
// the actual sazuctl CLI entry points: onboarding a KSK, registering a
// ZSK (add-zsk), authenticating a routine push with the ZSK alone,
// signing content with the ZSK while the KSK authenticates
// (push-update -zsk-key), and finally retiring it (retire-zsk) -- with
// the retired ZSK confirmed to no longer authenticate anything.
func TestE2EZSKFullLifecycle(t *testing.T) {
	addr := startTestServer(t)
	zone := "e2e-zsk.example."
	dir := t.TempDir()
	kskPath := filepath.Join(dir, "ksk.private")
	zskPath := filepath.Join(dir, "zsk.private")

	zoneFile := writeTestZoneFile(t, zone)
	if err := runPushZone([]string{"-zone", zone, "-key", kskPath, "-zonefile", zoneFile, "-target", addr}); err != nil {
		t.Fatalf("push-zone (onboarding): %v", err)
	}

	if err := runAddZSK([]string{"-zone", zone, "-ksk-key", kskPath, "-zsk-key", zskPath, "-target", addr}); err != nil {
		t.Fatalf("add-zsk: %v", err)
	}

	// The ZSK authenticates a routine push entirely on its own.
	if err := runPushUpdate([]string{
		"-zone", zone, "-key", zskPath,
		"-add", "zsk-authenticated." + zone + " 300 IN A 203.0.113.40",
		"-target", addr,
	}); err != nil {
		t.Fatalf("push-update authenticated by the ZSK: %v", err)
	}
	if answer := queryA(t, addr, "zsk-authenticated."+zone); len(answer) != 1 {
		t.Fatalf("expected the ZSK-authenticated push's content to be servable, got %d answers", len(answer))
	}

	// The KSK authenticates the transaction while the ZSK signs the
	// content (-zsk-key on push-update).
	if err := runPushUpdate([]string{
		"-zone", zone, "-key", kskPath, "-zsk-key", zskPath,
		"-add", "zsk-signed." + zone + " 300 IN A 203.0.113.50",
		"-target", addr,
	}); err != nil {
		t.Fatalf("push-update with -zsk-key: %v", err)
	}
	if answer := queryA(t, addr, "zsk-signed."+zone); len(answer) != 1 {
		t.Fatalf("expected the ZSK-signed push's content to be servable, got %d answers", len(answer))
	}

	if err := runRetireZSK([]string{"-zone", zone, "-ksk-key", kskPath, "-zsk-key", zskPath, "-target", addr}); err != nil {
		t.Fatalf("retire-zsk: %v", err)
	}

	// The retired ZSK no longer authenticates anything.
	if err := runPushUpdate([]string{
		"-zone", zone, "-key", zskPath,
		"-add", "after-retirement." + zone + " 300 IN A 198.51.100.2",
		"-target", addr,
	}); err == nil {
		t.Fatalf("expected a push authenticated by a retired ZSK to be rejected")
	}

	// The KSK still works normally.
	if err := runPushUpdate([]string{
		"-zone", zone, "-key", kskPath,
		"-add", "still-fine." + zone + " 300 IN A 203.0.113.60",
		"-target", addr,
	}); err != nil {
		t.Fatalf("push-update with the KSK after ZSK retirement: %v", err)
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

	zoneFile := writeTestZoneFile(t, zone)
	if err := runPushZone([]string{"-zone", zone, "-key", kskPath, "-zonefile", zoneFile, "-target", addr}); err != nil {
		t.Fatalf("push-zone (onboarding): %v", err)
	}
	if err := runAddZSK([]string{"-zone", zone, "-ksk-key", kskPath, "-zsk-key", oldZSKPath, "-target", addr}); err != nil {
		t.Fatalf("add-zsk (initial): %v", err)
	}

	if err := runRotateKey([]string{
		"-zone", zone, "-role", "zsk",
		"-key", kskPath, "-current-zsk-key", oldZSKPath, "-new-zsk-key", newZSKPath,
		"-target", addr,
	}); err != nil {
		t.Fatalf("rotate-key -role zsk: %v", err)
	}

	if err := runPushUpdate([]string{
		"-zone", zone, "-key", oldZSKPath,
		"-add", "should-fail." + zone + " 300 IN A 198.51.100.3",
		"-target", addr,
	}); err == nil {
		t.Fatalf("expected the old ZSK to no longer authenticate after rotate-key -role zsk")
	}

	if err := runPushUpdate([]string{
		"-zone", zone, "-key", newZSKPath,
		"-add", "should-succeed." + zone + " 300 IN A 203.0.113.70",
		"-target", addr,
	}); err != nil {
		t.Fatalf("push-update with the new ZSK after rotation: %v", err)
	}
	if answer := queryA(t, addr, "should-succeed."+zone); len(answer) != 1 {
		t.Fatalf("expected the new ZSK's push to be servable, got %d answers", len(answer))
	}
}

// TestE2EInitZoneThenPushZoneWithYAML exercises the "how do I even get
// a zone file to push" onboarding path end to end: init-zone writes a
// starter YAML zone definition, and push-zone accepts it directly as
// -zonefile (no separate conversion step) -- proving the YAML front end
// (zoneyaml.go) produces real, servable zone content through the actual
// CLI commands a customer would run.
func TestE2EInitZoneThenPushZoneWithYAML(t *testing.T) {
	addr := startTestServer(t)
	zone := "e2e-yaml-zone.example."
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "zone.yaml")
	kskPath := filepath.Join(dir, "ksk.private")

	if err := runInitZone([]string{"-zone", zone, "-out", yamlPath}); err != nil {
		t.Fatalf("init-zone: %v", err)
	}
	if _, err := os.Stat(yamlPath); err != nil {
		t.Fatalf("expected init-zone to create %s: %v", yamlPath, err)
	}

	if err := runPushZone([]string{"-zone", zone, "-key", kskPath, "-zonefile", yamlPath, "-target", addr}); err != nil {
		t.Fatalf("push-zone with a YAML zonefile: %v", err)
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
// output isn't just plausible-looking text -- push-zone can load and
// push the exact BIND-format file it produces from a YAML source.
func TestE2EZoneConvertProducesAPushableZoneFile(t *testing.T) {
	addr := startTestServer(t)
	zone := "e2e-zone-convert.example."
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "zone.yaml")
	zonePath := filepath.Join(dir, "zone.zone")
	kskPath := filepath.Join(dir, "ksk.private")

	if err := runInitZone([]string{"-zone", zone, "-out", yamlPath}); err != nil {
		t.Fatalf("init-zone: %v", err)
	}
	if err := runZoneConvert([]string{"-in", yamlPath, "-out", zonePath}); err != nil {
		t.Fatalf("zone-convert: %v", err)
	}

	if err := runPushZone([]string{"-zone", zone, "-key", kskPath, "-zonefile", zonePath, "-target", addr}); err != nil {
		t.Fatalf("push-zone with the converted BIND zone file: %v", err)
	}
	if answer := queryA(t, addr, "www."+zone); len(answer) != 1 {
		t.Fatalf("expected the converted zone file's www record to be servable, got %d answers", len(answer))
	}
}
