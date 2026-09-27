package sazu

import (
	"testing"
	"time"
)

func TestIPRateLimiterAllowsUpToTheLimitThenRefuses(t *testing.T) {
	r := NewIPRateLimiter(3)
	for i := 0; i < 3; i++ {
		if !r.Allow("203.0.113.1:5000") {
			t.Fatalf("attempt %d: expected within quota", i)
		}
	}
	if r.Allow("203.0.113.1:5001") {
		t.Fatalf("expected the 4th attempt to exceed the per-IP quota, even from a different source port")
	}
}

func TestIPRateLimiterTracksAddressesIndependently(t *testing.T) {
	r := NewIPRateLimiter(1)
	if !r.Allow("203.0.113.1:5000") {
		t.Fatalf("expected 203.0.113.1's first attempt within quota")
	}
	if !r.Allow("203.0.113.2:5000") {
		t.Fatalf("expected 203.0.113.2's quota to be entirely independent of 203.0.113.1's")
	}
	if r.Allow("203.0.113.1:6000") {
		t.Fatalf("expected 203.0.113.1's quota to already be exhausted, regardless of source port")
	}
}

// TestIPRateLimiterCoversManyDistinctZoneNamesFromOneAddress is the
// exact scenario IPRateLimiter exists for: an attacker probing many
// different, never-before-seen zone names from one address, each of
// which would otherwise get its own fresh, empty RateLimiter quota
// bucket. IPRateLimiter itself has no notion of "zone" at all -- it's
// keyed purely by address -- so this just proves that indifference
// directly: the same address is refused after its per-minute budget is
// used up, with each Allow call standing in for an attempt against a
// distinct zone name.
func TestIPRateLimiterCoversManyDistinctZoneNamesFromOneAddress(t *testing.T) {
	r := NewIPRateLimiter(5)
	addr := "203.0.113.9:40000"
	for i := 0; i < 5; i++ {
		if !r.Allow(addr) {
			t.Fatalf("attempt %d (simulating a distinct candidate zone name): expected within quota", i)
		}
	}
	if r.Allow(addr) {
		t.Fatalf("expected the 6th distinct-zone-name attempt from the same address to be refused")
	}
}

func TestIPRateLimiterSlidesTheWindow(t *testing.T) {
	r := NewIPRateLimiter(1)
	now := time.Now()
	r.now = func() time.Time { return now }
	if !r.Allow("203.0.113.1:5000") {
		t.Fatalf("expected the first attempt within quota")
	}
	if r.Allow("203.0.113.1:5000") {
		t.Fatalf("expected the quota to be exhausted immediately after")
	}

	r.now = func() time.Time { return now.Add(time.Minute + time.Second) }
	if !r.Allow("203.0.113.1:5000") {
		t.Fatalf("expected quota to be available again once the first attempt aged out of the rolling 1-minute window")
	}
}

func TestSourceIPStripsPort(t *testing.T) {
	if got := sourceIP("203.0.113.1:5353"); got != "203.0.113.1" {
		t.Fatalf("sourceIP(\"203.0.113.1:5353\") = %q, want %q", got, "203.0.113.1")
	}
	if got := sourceIP("[2001:db8::1]:5353"); got != "2001:db8::1" {
		t.Fatalf("sourceIP(IPv6 with port) = %q, want %q", got, "2001:db8::1")
	}
}

func TestSourceIPFallsBackToOriginalWhenNotHostPort(t *testing.T) {
	if got := sourceIP("not-a-host-port"); got != "not-a-host-port" {
		t.Fatalf("expected sourceIP to fall back to the original string, got %q", got)
	}
}

// TestIPRateLimiterCountsIPv6PerSlash64: addresses anywhere in one IPv6
// /64 share a bucket; a different /64 gets its own.
func TestIPRateLimiterCountsIPv6PerSlash64(t *testing.T) {
	r := NewIPRateLimiter(2)
	if !r.Allow("[2001:db8:1:2::1]:5353") || !r.Allow("[2001:db8:1:2:ffff::9]:5353") {
		t.Fatalf("expected the first two attempts from one /64 to be allowed")
	}
	if r.Allow("[2001:db8:1:2:dead:beef::1]:40000") {
		t.Fatalf("expected a third address in the same /64 to share the exhausted bucket")
	}
	if !r.Allow("[2001:db8:1:3::1]:5353") {
		t.Fatalf("expected a different /64 to have its own bucket")
	}
}

func TestRateLimitKey(t *testing.T) {
	cases := map[string]string{
		"203.0.113.1:5353":            "203.0.113.1",
		"[::ffff:203.0.113.1]:5353":   "203.0.113.1",
		"[2001:db8:1:2:3:4:5:6]:5353": "2001:db8:1:2::/64",
		"not-a-host-port":             "not-a-host-port",
	}
	for in, want := range cases {
		if got := rateLimitKey(in); got != want {
			t.Errorf("rateLimitKey(%q) = %q, want %q", in, got, want)
		}
	}
}
