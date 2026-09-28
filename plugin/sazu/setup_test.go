package sazu

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
)

func TestParseSazu(t *testing.T) {
	tests := []struct {
		input        string
		shouldErr    bool
		wantZones    []string
		wantInsecure bool
		wantDBPath   string
	}{
		{
			input:     `sazu example.org.`,
			wantZones: []string{"example.org."},
		},
		{
			input: `sazu example.org. {
				rate_limit 10
			}`,
			shouldErr: true,
		},
		{
			input: `sazu example.org. {
				rate_limit ten 100
			}`,
			shouldErr: true,
		},
		{
			input: `sazu example.org. {
				rate_limit -1 100
			}`,
			shouldErr: true,
		},
		{
			input: `sazu example.org. {
				ip_rate_limit
			}`,
			shouldErr: true,
		},
		{
			input: `sazu example.org. {
				ip_rate_limit ten
			}`,
			shouldErr: true,
		},
		{
			input: `sazu example.org. {
				ip_rate_limit -1
			}`,
			shouldErr: true,
		},
		{
			input: `sazu example.org. {
				ip_rate_limit 10 20
			}`,
			shouldErr: true,
		},
		{
			input:     `sazu example.org. example.net.`,
			wantZones: []string{"example.org.", "example.net."},
		},
		{
			input: `sazu example.org. {
				insecure_skip_chain_validation
			}`,
			wantZones:    []string{"example.org."},
			wantInsecure: true,
		},
		{
			input: `sazu example.org. {
				db /tmp/sazu-test.db
			}`,
			wantZones:  []string{"example.org."},
			wantDBPath: "/tmp/sazu-test.db",
		},
		{
			input: `sazu example.org. {
				insecure_skip_chain_validation
				db /tmp/sazu-test.db
			}`,
			wantZones:    []string{"example.org."},
			wantInsecure: true,
			wantDBPath:   "/tmp/sazu-test.db",
		},
		{
			input: `sazu example.org. {
				db
			}`,
			shouldErr: true,
		},
		{
			input: `sazu example.org. {
				db /tmp/a /tmp/b
			}`,
			shouldErr: true,
		},
		{
			input: `sazu example.org. {
				insecure_skip_chain_validation extra
			}`,
			shouldErr: true,
		},
		{
			input: `sazu example.org. {
				bogus
			}`,
			shouldErr: true,
		},
	}

	for i, tc := range tests {
		c := caddy.NewTestController("dns", tc.input)
		cfg, err := parseSazu(c)
		if tc.shouldErr {
			if err == nil {
				t.Errorf("test %d: expected an error, got none", i)
			}
			continue
		}
		if err != nil {
			t.Fatalf("test %d: unexpected error: %v", i, err)
		}
		if len(cfg.zones) != len(tc.wantZones) {
			t.Fatalf("test %d: got zones %v, want %v", i, cfg.zones, tc.wantZones)
		}
		for j, z := range tc.wantZones {
			if cfg.zones[j] != z {
				t.Fatalf("test %d: zone %d = %q, want %q", i, j, cfg.zones[j], z)
			}
		}
		if cfg.insecureSkipChainValidation != tc.wantInsecure {
			t.Fatalf("test %d: insecureSkipChainValidation = %v, want %v", i, cfg.insecureSkipChainValidation, tc.wantInsecure)
		}
		if cfg.dbPath != tc.wantDBPath {
			t.Fatalf("test %d: dbPath = %q, want %q", i, cfg.dbPath, tc.wantDBPath)
		}
	}
}

func TestParseSazuRateLimitDefaultsAndOverride(t *testing.T) {
	c := caddy.NewTestController("dns", `sazu example.org.`)
	cfg, err := parseSazu(c)
	if err != nil {
		t.Fatalf("parseSazu: %v", err)
	}
	if cfg.fullPushesPerDay != DefaultFullPushesPerDay || cfg.keyManagementPushesPerDay != DefaultKeyManagementPushesPerDay {
		t.Fatalf("expected default quotas (%d, %d) when rate_limit is omitted, got (%d, %d)",
			DefaultFullPushesPerDay, DefaultKeyManagementPushesPerDay, cfg.fullPushesPerDay, cfg.keyManagementPushesPerDay)
	}

	c = caddy.NewTestController("dns", `sazu example.org. {
		rate_limit 10 100
	}`)
	cfg, err = parseSazu(c)
	if err != nil {
		t.Fatalf("parseSazu: %v", err)
	}
	if cfg.fullPushesPerDay != 10 || cfg.keyManagementPushesPerDay != 100 {
		t.Fatalf("expected overridden quotas (10, 100), got (%d, %d)", cfg.fullPushesPerDay, cfg.keyManagementPushesPerDay)
	}
}

func TestParseSazuIPRateLimitDefaultAndOverride(t *testing.T) {
	c := caddy.NewTestController("dns", `sazu example.org.`)
	cfg, err := parseSazu(c)
	if err != nil {
		t.Fatalf("parseSazu: %v", err)
	}
	if cfg.ipUpdatesPerMinute != DefaultIPUpdatesPerMinute {
		t.Fatalf("expected the default per-IP quota (%d) when ip_rate_limit is omitted, got %d",
			DefaultIPUpdatesPerMinute, cfg.ipUpdatesPerMinute)
	}

	c = caddy.NewTestController("dns", `sazu example.org. {
		ip_rate_limit 5
	}`)
	cfg, err = parseSazu(c)
	if err != nil {
		t.Fatalf("parseSazu: %v", err)
	}
	if cfg.ipUpdatesPerMinute != 5 {
		t.Fatalf("expected the overridden per-IP quota (5), got %d", cfg.ipUpdatesPerMinute)
	}
}

func TestSetupWiresPluginAndOptionalDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sazu.db")
	input := `sazu example.org. {
		insecure_skip_chain_validation
		db ` + dbPath + `
	}`
	c := caddy.NewTestController("dns", input)
	if err := setup(c); err != nil {
		t.Fatalf("setup: %v", err)
	}
}

func TestSetupWithoutDBIsPurelyInMemory(t *testing.T) {
	c := caddy.NewTestController("dns", `sazu example.org.`)
	if err := setup(c); err != nil {
		t.Fatalf("setup: %v", err)
	}
}

func TestParseSazuMaxSIG0LifetimeAndTrustAnchor(t *testing.T) {
	c := caddy.NewTestController("dns", `sazu example.org.`)
	cfg, err := parseSazu(c)
	if err != nil {
		t.Fatalf("parseSazu: %v", err)
	}
	if cfg.maxSIG0Lifetime != DefaultMaxSIG0Lifetime || cfg.trustAnchorPath != "" {
		t.Fatalf("expected defaults, got lifetime=%s anchor=%q", cfg.maxSIG0Lifetime, cfg.trustAnchorPath)
	}

	c = caddy.NewTestController("dns", `sazu example.org. {
		max_sig0_lifetime 10m
		trust_anchor /etc/unbound/root.key
	}`)
	cfg, err = parseSazu(c)
	if err != nil {
		t.Fatalf("parseSazu: %v", err)
	}
	if cfg.maxSIG0Lifetime != 10*time.Minute || cfg.trustAnchorPath != "/etc/unbound/root.key" {
		t.Fatalf("expected overrides, got lifetime=%s anchor=%q", cfg.maxSIG0Lifetime, cfg.trustAnchorPath)
	}

	for _, bad := range []string{
		"max_sig0_lifetime",
		"max_sig0_lifetime soon",
		"max_sig0_lifetime -5m",
		"trust_anchor",
		"trust_anchor a b",
	} {
		c = caddy.NewTestController("dns", "sazu example.org. {\n"+bad+"\n}")
		if _, err := parseSazu(c); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

// TestSetupRejectsUnreadableTrustAnchorFile: a configured trust anchor
// file that can't be loaded fails setup rather than silently falling
// back to the built-in anchors.
func TestSetupRejectsUnreadableTrustAnchorFile(t *testing.T) {
	c := caddy.NewTestController("dns", `sazu example.org. {
		trust_anchor `+filepath.Join(t.TempDir(), "missing.key")+`
	}`)
	if err := setup(c); err == nil {
		t.Fatalf("expected setup to fail for a missing trust anchor file")
	}
}

func TestParseSazuRolloverHoldDown(t *testing.T) {
	cfg, err := parseSazu(caddy.NewTestController("dns", `sazu example.org.`))
	if err != nil || cfg.rolloverHoldDown != DefaultRolloverHoldDown {
		t.Fatalf("expected the default hold-down, got %s (%v)", cfg.rolloverHoldDown, err)
	}
	cfg, err = parseSazu(caddy.NewTestController("dns", "sazu example.org. {\nrollover_hold_down 0s\n}"))
	if err != nil || cfg.rolloverHoldDown != 0 {
		t.Fatalf("expected 0 to disable the hold-down, got %s (%v)", cfg.rolloverHoldDown, err)
	}
	for _, bad := range []string{"rollover_hold_down", "rollover_hold_down -1h", "rollover_hold_down soon"} {
		if _, err := parseSazu(caddy.NewTestController("dns", "sazu example.org. {\n"+bad+"\n}")); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestSetupConventions(t *testing.T) {
	for _, input := range []string{
		"sazu example.org.\nsazu example.net.",
		`sazu example.org. {
			no_such_option
		}`,
	} {
		if err := setup(caddy.NewTestController("dns", input)); err == nil {
			t.Errorf("expected an error for %q", input)
		}
	}
}

// TestSetupResolvesPathsBelowRoot: relative db and trust_anchor paths are
// relative to the root plugin's directory.
func TestSetupResolvesPathsBelowRoot(t *testing.T) {
	root := t.TempDir()
	c := caddy.NewTestController("dns", `sazu example.org. {
		db sazu.db
	}`)
	dnsserver.GetConfig(c).Root = root
	if err := setup(c); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "sazu.db")); err != nil {
		t.Fatalf("expected the database below root: %v", err)
	}
	if got := underRoot(root, "/abs/anchors.xml"); got != "/abs/anchors.xml" {
		t.Fatalf("an absolute path must be kept, got %q", got)
	}
}

func TestCacheBypassZones(t *testing.T) {
	s := newTestSazu("example.org.")
	if got := s.CacheBypassZones(); len(got) != 1 || got[0] != "example.org." {
		t.Fatalf("CacheBypassZones = %v", got)
	}
}
