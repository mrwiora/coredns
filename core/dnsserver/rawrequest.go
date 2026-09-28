package dnsserver

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// RawRequestKey is the context key under which the exact DNS wire bytes of
// a request are available to plugins, for request opcodes a plugin asked
// for with Config.CaptureRawRequests. Some authentication schemes (SIG(0),
// RFC 2931) sign the literal bytes a client sent, which a re-encoding of
// the parsed *dns.Msg does not reproduce.
//
// Over DNS over HTTPS, HTTP/3, QUIC and gRPC the value is the request body
// the message was parsed from. Over UDP, TCP and TLS, miekg/dns hands the
// handler only the parsed message, so the bytes are captured as they are
// read and matched to the request by transport, source address and message
// ID. That match is a correlation, not a guarantee: a plugin that relies on
// the bytes MUST parse them and act on that message only, never on the
// *dns.Msg it was handed.
type RawRequestKey struct{}

const (
	rawCaptureTTL      = 5 * time.Second
	rawCaptureCapacity = 4096
)

// rawCapture holds the raw bytes of requests read on a Server's UDP, TCP
// and TLS listeners until the handler for the same request claims them.
// Only requests whose opcode is in opcodes are kept, so a flood of
// ordinary queries can't evict them. Unclaimed entries (a request dropped
// before reaching the handler) are bounded by a TTL and a capacity.
type rawCapture struct {
	opcodes map[int]struct{}

	mu      sync.Mutex
	entries map[rawKey]rawEntry
	order   []rawKey // insertion order, oldest first, for capacity eviction
}

type rawKey struct {
	network string
	addr    string
	id      uint16
}

type rawEntry struct {
	raw     []byte
	expires time.Time
}

func newRawCapture(opcodes map[int]struct{}) *rawCapture {
	if len(opcodes) == 0 {
		return nil
	}
	return &rawCapture{opcodes: opcodes, entries: make(map[rawKey]rawEntry)}
}

// wants reports whether a request with this raw header is captured.
func (c *rawCapture) wants(m []byte) bool {
	if len(m) < 12 || m[2]&0x80 != 0 { // too short, or a response
		return false
	}
	_, ok := c.opcodes[int(m[2]>>3)&0x0f]
	return ok
}

func (c *rawCapture) put(addr net.Addr, m []byte) {
	if addr == nil || !c.wants(m) {
		return
	}
	key := rawKey{network: addr.Network(), addr: addr.String(), id: binary.BigEndian.Uint16(m[0:2])}
	entry := rawEntry{raw: append([]byte(nil), m...), expires: time.Now().Add(rawCaptureTTL)}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists && len(c.entries) >= rawCaptureCapacity {
		for len(c.order) > 0 {
			oldest := c.order[0]
			c.order = c.order[1:]
			if _, ok := c.entries[oldest]; ok {
				delete(c.entries, oldest)
				break
			}
		}
	}
	c.entries[key] = entry
	c.order = append(c.order, key)
}

func (c *rawCapture) take(addr net.Addr, id uint16) ([]byte, bool) {
	key := rawKey{network: addr.Network(), addr: addr.String(), id: id}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	delete(c.entries, key)
	if len(c.entries) == 0 {
		c.order = c.order[:0]
	}
	return entry.raw, time.Now().Before(entry.expires)
}

// decorate returns the dns.DecorateReader that feeds c.
func (c *rawCapture) decorate(r dns.Reader) dns.Reader {
	pcr, _ := r.(dns.PacketConnReader)
	return &capturingReader{inner: r, innerPC: pcr, capture: c}
}

// capturingReader records requests as miekg/dns reads them. Whether the
// server calls ReadUDP or ReadPacketConn depends on the PacketConn's
// concrete type (a reuseport or PROXY protocol wrapper uses the latter).
type capturingReader struct {
	inner   dns.Reader
	innerPC dns.PacketConnReader
	capture *rawCapture
}

func (r *capturingReader) ReadTCP(conn net.Conn, timeout time.Duration) ([]byte, error) {
	m, err := r.inner.ReadTCP(conn, timeout)
	if err == nil {
		r.capture.put(conn.RemoteAddr(), m)
	}
	return m, err
}

func (r *capturingReader) ReadUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *dns.SessionUDP, error) {
	m, s, err := r.inner.ReadUDP(conn, timeout)
	if err == nil && s != nil {
		r.capture.put(s.RemoteAddr(), m)
	}
	return m, s, err
}

func (r *capturingReader) ReadPacketConn(conn net.PacketConn, timeout time.Duration) ([]byte, net.Addr, error) {
	m, addr, err := r.innerPC.ReadPacketConn(conn, timeout)
	if err == nil {
		r.capture.put(addr, m)
	}
	return m, addr, err
}

// decorateReader returns the reader decorator for s's UDP, TCP and TLS
// listeners, or nil when no config asked for raw requests.
func (s *Server) decorateReader() dns.DecorateReader {
	if s.rawCapture == nil {
		return nil
	}
	return s.rawCapture.decorate
}

// withRawRequest claims the captured bytes of r, if it is a request whose
// opcode is captured, and puts them on ctx under RawRequestKey. Claiming
// happens for every such request, whatever the plugins do next, so entries
// don't linger.
func (s *Server) withRawRequest(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) context.Context {
	if s.rawCapture == nil || r == nil {
		return ctx
	}
	if _, ok := s.rawCapture.opcodes[r.Opcode]; !ok || r.Response {
		return ctx
	}
	if raw, ok := s.rawCapture.take(w.RemoteAddr(), r.Id); ok {
		return context.WithValue(ctx, RawRequestKey{}, raw)
	}
	return ctx
}

// withRawBody puts body, the exact bytes req was parsed from, on ctx when
// req's opcode is captured. For transports that parse the request
// themselves (HTTPS, HTTP/3, QUIC, gRPC).
func (s *Server) withRawBody(ctx context.Context, req *dns.Msg, body []byte) context.Context {
	if len(s.rawCaptureOpcodes) == 0 || req == nil {
		return ctx
	}
	if _, ok := s.rawCaptureOpcodes[req.Opcode]; !ok {
		return ctx
	}
	return context.WithValue(ctx, RawRequestKey{}, body)
}
