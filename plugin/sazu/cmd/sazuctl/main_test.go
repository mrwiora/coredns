package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestGuidanceTemplatesRenderWithoutError proves every embedded guidance
// template (guidance/*.txt) actually executes against the data type its
// caller passes it -- template.Must at package init only catches a
// syntax error, not a template referencing a field its data struct
// doesn't have, which only fails at Execute time. Also a basic sanity
// check that no template silently renders empty.
func TestGuidanceTemplatesRenderWithoutError(t *testing.T) {
	dsData := dsGuidanceData{
		Zone: "example.org.", Owner: "example.org.",
		KeyTag: 12345, Algorithm: 15, AlgorithmName: "ED25519",
		DigestType: 2, Digest: "abcd1234",
		KeyTypeValue: 257, KeyTypeLabel: "KSK",
		PublicKeyB64: "AAAA",
	}
	rotateData := rotateKeyChoiceData{Zone: "example.org.", HasZSK: true, ZSKKeyTag: 54321}

	cases := []struct {
		name string
		data any
	}{
		{"no-ds.txt", dsData},
		{"unknown-signer.txt", dsData},
		{"rotate-key-choice.txt", rotateData},
		{"rotate-key-choice.txt", rotateKeyChoiceData{Zone: "example.org.", HasZSK: false}},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		if err := guidanceTemplates.ExecuteTemplate(&buf, c.name, c.data); err != nil {
			t.Fatalf("executing %s: %v", c.name, err)
		}
		if buf.Len() == 0 {
			t.Fatalf("expected %s to render non-empty output", c.name)
		}
	}
}

// TestNoDSGuidanceIncludesTheDSRecordAndZone proves the rendered output
// actually contains the concrete, actionable values a customer needs --
// not just that the template executes without error.
func TestNoDSGuidanceIncludesTheDSRecordAndZone(t *testing.T) {
	var buf bytes.Buffer
	data := dsGuidanceData{
		Zone: "example.org.", Owner: "example.org.",
		KeyTag: 12345, Algorithm: 15, AlgorithmName: "ED25519",
		DigestType: 2, Digest: "deadbeef",
		KeyTypeValue: 257, KeyTypeLabel: "KSK",
		PublicKeyB64: "base64stuff",
	}
	if err := guidanceTemplates.ExecuteTemplate(&buf, "no-ds.txt", data); err != nil {
		t.Fatalf("executing no-ds.txt: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"example.org.", "12345", "deadbeef", "base64stuff", "dig DS example.org. +short"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected rendered no-ds.txt to contain %q, got:\n%s", want, out)
		}
	}
}

// TestRotateKeyChoiceGuidanceReflectsWhetherAZSKExists proves the
// decision text actually branches on HasZSK, rather than always
// printing the same generic advice regardless of the zone's real state.
func TestRotateKeyChoiceGuidanceReflectsWhetherAZSKExists(t *testing.T) {
	var withZSK, withoutZSK bytes.Buffer
	if err := guidanceTemplates.ExecuteTemplate(&withZSK, "rotate-key-choice.txt",
		rotateKeyChoiceData{Zone: "example.org.", HasZSK: true, ZSKKeyTag: 999}); err != nil {
		t.Fatalf("executing with HasZSK=true: %v", err)
	}
	if err := guidanceTemplates.ExecuteTemplate(&withoutZSK, "rotate-key-choice.txt",
		rotateKeyChoiceData{Zone: "example.org.", HasZSK: false}); err != nil {
		t.Fatalf("executing with HasZSK=false: %v", err)
	}
	if !strings.Contains(withZSK.String(), "999") {
		t.Fatalf("expected the existing ZSK's key tag to appear when HasZSK is true, got:\n%s", withZSK.String())
	}
	if strings.Contains(withoutZSK.String(), "add-zsk -zone example.org. -ksk-key") == false {
		t.Fatalf("expected guidance to register a ZSK first when none exists yet, got:\n%s", withoutZSK.String())
	}
	if withZSK.String() == withoutZSK.String() {
		t.Fatalf("expected the two HasZSK states to render different guidance")
	}
}

// TestKeyTypeLabelAndAlgorithmLabel proves the small display helpers the
// guidance templates and printKeyInfo depend on are correct.
func TestKeyTypeLabelAndAlgorithmLabel(t *testing.T) {
	if got := keyTypeLabel(257); got != "KSK" {
		t.Fatalf("keyTypeLabel(257) = %q, want KSK", got)
	}
	if got := keyTypeLabel(256); got != "ZSK" {
		t.Fatalf("keyTypeLabel(256) = %q, want ZSK", got)
	}
	if got := keyTypeLabel(1); got != "unrecognized flags" {
		t.Fatalf("keyTypeLabel(1) = %q, want \"unrecognized flags\"", got)
	}
	if got := algorithmLabel(15); got != "ED25519" {
		t.Fatalf("algorithmLabel(15) = %q, want ED25519", got)
	}
}

// TestParseRoleFlag proves the -role flag's three cases -- accepted,
// accepted, and rejected -- since add-zsk/retire-zsk/rotate-key/keygen
// all depend on it to decide whether a key is a KSK or a ZSK.
func TestParseRoleFlag(t *testing.T) {
	if ksk, err := parseRoleFlag("ksk"); err != nil || !ksk {
		t.Fatalf(`parseRoleFlag("ksk") = %v, %v; want true, nil`, ksk, err)
	}
	if ksk, err := parseRoleFlag("zsk"); err != nil || ksk {
		t.Fatalf(`parseRoleFlag("zsk") = %v, %v; want false, nil`, ksk, err)
	}
	if _, err := parseRoleFlag("neither"); err == nil {
		t.Fatalf(`parseRoleFlag("neither") = nil error, want an error`)
	}
}

// TestChooseNetworkDefaultsToTCPRegardlessOfSize proves the central
// transport-selection change: without -udp (allowUDP=false), the
// answer is always "tcp" -- for a tiny message and for one far larger
// than any UDP datagram could carry -- never chosen by size the way an
// earlier version of this tool did.
func TestChooseNetworkDefaultsToTCPRegardlessOfSize(t *testing.T) {
	if network, warn := chooseNetwork(50, false); network != "tcp" || warn != "" {
		t.Fatalf("chooseNetwork(50, false) = %q, %q; want tcp, no warning", network, warn)
	}
	if network, warn := chooseNetwork(50000, false); network != "tcp" || warn != "" {
		t.Fatalf("chooseNetwork(50000, false) = %q, %q; want tcp, no warning", network, warn)
	}
}

// TestChooseNetworkAllowUDPUsesUDPWhenItFits proves -udp actually
// opts into UDP when the message is small enough to be safe.
func TestChooseNetworkAllowUDPUsesUDPWhenItFits(t *testing.T) {
	if network, warn := chooseNetwork(safeUDPPushSize, true); network != "udp" || warn != "" {
		t.Fatalf("chooseNetwork(safeUDPPushSize, true) = %q, %q; want udp, no warning", network, warn)
	}
	if network, warn := chooseNetwork(1, true); network != "udp" || warn != "" {
		t.Fatalf("chooseNetwork(1, true) = %q, %q; want udp, no warning", network, warn)
	}
}

// TestChooseNetworkAllowUDPFallsBackToTCPWithWarningWhenTooLarge proves
// -udp doesn't send a datagram doomed to be truncated or dropped: past
// the safe UDP size, it falls back to TCP and says why.
func TestChooseNetworkAllowUDPFallsBackToTCPWithWarningWhenTooLarge(t *testing.T) {
	network, warn := chooseNetwork(safeUDPPushSize+1, true)
	if network != "tcp" {
		t.Fatalf("chooseNetwork(safeUDPPushSize+1, true) network = %q, want tcp", network)
	}
	if warn == "" {
		t.Fatalf("expected a non-empty warning explaining the fallback")
	}
	if !strings.Contains(warn, "TCP") || !strings.Contains(warn, "513") {
		t.Fatalf("expected the warning to mention TCP and the actual size, got %q", warn)
	}
}

// TestRunPublishZoneRejectsUnknownDenialOfExistenceValue proves an
// unrecognized -denial-of-existence value is rejected up front, before
// runPublishZone ever tries to load a key or zone file -- nsec3 and nsec
// are the only two authenticated denial-of-existence proofs this package
// knows how to build (see BuildContentPushNSEC3/BuildContentPush).
func TestRunPublishZoneRejectsUnknownDenialOfExistenceValue(t *testing.T) {
	err := runPublishZone([]string{
		"-zone", "example.org.", "-zsk-key", "/nonexistent", "-zonefile", "/nonexistent",
		"-denial-of-existence", "nsec5",
	})
	if err == nil {
		t.Fatal("expected an error for an unrecognized -denial-of-existence value")
	}
	if !strings.Contains(err.Error(), "-denial-of-existence") {
		t.Fatalf("expected the error to name -denial-of-existence, got %q", err)
	}
}

// TestAddZSKRetireZSKAndRotateKeyKSKRequireTarget proves -target is
// enforced as required (not merely conventional) for the three commands
// that need to query a zone's current DNSKEY set live before they can
// correctly sign a change to it -- see fetchCurrentDNSKEYs' own doc
// comment for why omitting it can no longer be treated as "just print
// the wire bytes" the way every other subcommand still allows.
func TestAddZSKRetireZSKAndRotateKeyKSKRequireTarget(t *testing.T) {
	cases := []struct {
		name string
		run  func() error
	}{
		{"add-zsk", func() error {
			return runAddZSK([]string{"-zone", "example.org.", "-ksk-key", "/nonexistent", "-zsk-key", "/nonexistent"})
		}},
		{"retire-zsk", func() error {
			return runRetireZSK([]string{"-zone", "example.org.", "-ksk-key", "/nonexistent", "-zsk-key", "/nonexistent"})
		}},
		{"rotate-key -role ksk", func() error {
			return runRotateKey([]string{"-zone", "example.org.", "-role", "ksk", "-key", "/nonexistent", "-new-key", "/nonexistent"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil {
				t.Fatalf("expected an error when -target is omitted")
			}
			if !strings.Contains(err.Error(), "-target") {
				t.Fatalf("expected the error to name -target, got %q", err)
			}
		})
	}
}
