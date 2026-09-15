package sazu

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestUpdateLockForIsStableForTheSameZone proves updateLockFor is a
// pure function of the zone name -- the same (case- and FQDN-
// normalized) zone always maps to the same lock stripe, which is what
// actually makes it serialize updates to that zone correctly.
func TestUpdateLockForIsStableForTheSameZone(t *testing.T) {
	s := newTestSazu(".")
	a := s.updateLockFor("Example.ORG.")
	b := s.updateLockFor("example.org")
	if a != b {
		t.Fatalf("expected case/FQDN-insensitive zone names to map to the same lock stripe")
	}
}

// TestUpdateLockForSpreadsAcrossStripes proves the whole point of
// striping: a reasonable number of distinct zone names doesn't all
// collide onto one lock the way a single global mutex would.
func TestUpdateLockForSpreadsAcrossStripes(t *testing.T) {
	s := newTestSazu(".")
	seen := make(map[*sync.Mutex]bool)
	for i := 0; i < 200; i++ {
		seen[s.updateLockFor(fmt.Sprintf("zone-%d.example.", i))] = true
	}
	if len(seen) < zoneLockStripes/2 {
		t.Fatalf("expected 200 distinct zone names to spread across most of the %d stripes, only hit %d", zoneLockStripes, len(seen))
	}
}

// delayValidator is a ChainValidator that sleeps for delay when asked
// about slowZone specifically, and returns success immediately for
// every other zone -- standing in for a real chain-of-trust walk's
// outbound network round trip, without an actual network dependency.
type delayValidator struct {
	delay    time.Duration
	slowZone string
}

func (d delayValidator) VerifyChainOfTrust(zone string, _ *dns.DNSKEY) error {
	if zone == d.slowZone {
		time.Sleep(d.delay)
	}
	return nil
}

// sendRawNoFatal is sendRaw without the t.Fatalf calls -- for use from
// a background goroutine that isn't the one running the test function,
// where calling t.FailNow (what t.Fatalf does) would only exit that
// goroutine via runtime.Goexit without ever sending to a channel the
// main goroutine is waiting on, hanging the test instead of failing it
// cleanly. Same wire format (RFC 1035 §4.2.2 TCP length-prefix framing)
// as sendRaw, just reporting failure through an error return instead.
func sendRawNoFatal(addr string, wire []byte, timeout time.Duration) (*dns.Msg, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	var lenPrefix [2]byte
	binary.BigEndian.PutUint16(lenPrefix[:], uint16(len(wire)))
	if _, err := conn.Write(lenPrefix[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, lenPrefix[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, binary.BigEndian.Uint16(lenPrefix[:]))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(buf); err != nil {
		return nil, err
	}
	return resp, nil
}

// TestConcurrentUpdatesToDifferentZonesDoNotSerialize proves the actual
// point of replacing the single global updateMu with per-zone lock
// stripes: a slow first-contact chain-of-trust walk for one zone no
// longer blocks an unrelated, already-authenticated push to a different
// zone for its entire duration.
func TestConcurrentUpdatesToDifferentZonesDoNotSerialize(t *testing.T) {
	const slowDelay = 800 * time.Millisecond
	s := newTestSazu(".")
	s.InsecureSkipChainValidation = false
	s.Validator = delayValidator{delay: slowDelay, slowZone: "slow.example."}
	addr := serveThroughRealServer(t, s)

	// Onboard "fast.example." up front -- its own first contact isn't
	// slowed (delayValidator only sleeps for "slow.example."), so this
	// completes immediately.
	fastKey, fastPriv, err := GenerateEd25519Key("fast.example.", true)
	if err != nil {
		t.Fatalf("generating fast zone key: %v", err)
	}
	fastOnboard, err := BuildFullZonePush("fast.example.", synthesizeSOA("fast.example."), nil, fastKey, fastPriv, nil)
	if err != nil {
		t.Fatalf("building fast zone onboarding push: %v", err)
	}
	now := time.Now()
	fastWire, err := SignUpdate(fastOnboard, fastKey, fastPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing fast zone onboarding push: %v", err)
	}
	if resp := sendRaw(t, addr, fastWire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("onboarding fast.example. rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	// Start slow.example.'s first contact in the background -- its
	// chain-of-trust walk will sleep for slowDelay while holding
	// slow.example.'s lock stripe. Uses sendRawNoFatal (see its own doc
	// comment) rather than the shared sendRaw helper, since this runs on
	// a goroutine that isn't the one running the test function.
	slowKey, slowPriv, err := GenerateEd25519Key("slow.example.", true)
	if err != nil {
		t.Fatalf("generating slow zone key: %v", err)
	}
	slowOnboard, err := BuildFullZonePush("slow.example.", synthesizeSOA("slow.example."), nil, slowKey, slowPriv, nil)
	if err != nil {
		t.Fatalf("building slow zone onboarding push: %v", err)
	}
	now = time.Now()
	slowWire, err := SignUpdate(slowOnboard, slowKey, slowPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing slow zone onboarding push: %v", err)
	}
	type result struct {
		resp *dns.Msg
		err  error
	}
	slowDone := make(chan result, 1)
	go func() {
		resp, err := sendRawNoFatal(addr, slowWire, slowDelay+5*time.Second)
		slowDone <- result{resp, err}
	}()

	// Give the goroutine above a moment to actually reach and start
	// sleeping inside the chain-of-trust walk before racing it below.
	time.Sleep(slowDelay / 4)

	// While slow.example.'s onboarding is still in flight, push an
	// ordinary partial update to the already-onboarded
	// fast.example. -- this must complete quickly, not wait for
	// slow.example.'s chain walk to finish.
	now = time.Now()
	signedWWW, err := SignZoneContent([]dns.RR{testA("www.fast.example.", net.IPv4(203, 0, 113, 10))}, fastKey, fastPriv, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
	if err != nil {
		t.Fatalf("SignZoneContent: %v", err)
	}
	partial := new(dns.Msg)
	partial.SetQuestion("fast.example.", dns.TypeSOA)
	partial.Opcode = dns.OpcodeUpdate
	partial.Insert(signedWWW)
	partialWire, err := SignUpdate(partial, fastKey, fastPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing fast zone partial push: %v", err)
	}

	start := time.Now()
	resp := sendRaw(t, addr, partialWire)
	elapsed := time.Since(start)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("fast zone partial push rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if elapsed > slowDelay/2 {
		t.Fatalf("expected fast.example.'s push to complete well within slowDelay (%s) despite slow.example.'s in-flight chain walk, took %s", slowDelay, elapsed)
	}

	select {
	case r := <-slowDone:
		if r.err != nil {
			t.Fatalf("slow.example. onboarding: %v", r.err)
		}
		if r.resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("slow.example. onboarding rcode = %s, want NOERROR", dns.RcodeToString[r.resp.Rcode])
		}
	case <-time.After(slowDelay + 10*time.Second):
		t.Fatalf("slow.example. onboarding never completed")
	}
}

// TestConcurrentUpdatesToSameZoneStillSerializeCorrectly proves the
// other half of the property that matters: switching from one global
// lock to per-zone stripes must not weaken correctness for updates
// against the *same* zone. A burst of concurrent partial pushes,
// each adding one distinct record, must all still apply -- no update
// silently lost to a race the old single mutex would have prevented by
// brute force.
func TestConcurrentUpdatesToSameZoneStillSerializeCorrectly(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)

	key, priv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	onboard, err := BuildFullZonePush("example.org.", testSOA(1), nil, key, priv, nil)
	if err != nil {
		t.Fatalf("building onboarding push: %v", err)
	}
	now := time.Now()
	wire, err := SignUpdate(onboard, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing onboarding push: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("onboarding push rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	const n = 20
	var wg sync.WaitGroup
	rcodes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			now := time.Now()
			signedRR, err := SignZoneContent([]dns.RR{testA(fmt.Sprintf("rec%d.example.org.", i), net.IPv4(203, 0, 113, byte(i)))},
				key, priv, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
			if err != nil {
				t.Errorf("signing content for push %d: %v", i, err)
				return
			}
			partial := new(dns.Msg)
			partial.SetQuestion("example.org.", dns.TypeSOA)
			partial.Opcode = dns.OpcodeUpdate
			partial.Insert(signedRR)
			w, err := SignUpdate(partial, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
			if err != nil {
				t.Errorf("signing push %d: %v", i, err)
				return
			}
			rcodes[i] = sendRaw(t, addr, w).Rcode
		}(i)
	}
	wg.Wait()

	for i, rc := range rcodes {
		if rc != dns.RcodeSuccess {
			t.Fatalf("push %d rcode = %s, want NOERROR", i, dns.RcodeToString[rc])
		}
	}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("rec%d.example.org.", i)
		if answer := query(t, addr, name, dns.TypeA); len(answer.Answer) != 1 {
			t.Fatalf("expected %s to be servable after %d concurrent pushes, got %d answers", name, n, len(answer.Answer))
		}
	}
}
