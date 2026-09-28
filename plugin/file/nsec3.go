package file

import (
	"strings"

	"github.com/coredns/coredns/plugin/file/tree"

	"github.com/miekg/dns"
)

// Authenticated denial of existence from a zone's stored NSEC or NSEC3
// records. The zone is signed offline; these functions select the stored
// records a response needs (RFC 4035 §3.1.3, RFC 5155 §7.2), they never
// create any.
//
// NSEC3 records and their RRSIGs are kept in Apex.NSEC3, a tree of their
// own: their owner names are hashes, not names of the zone.

// denial collects the denial records for one response, each owner once.
type denial struct {
	z    *Zone
	ap   Apex
	tr   *tree.Tree
	do   bool
	out  []dns.RR
	seen map[string]bool
}

func (z *Zone) denial(ap Apex, tr *tree.Tree, do bool) *denial {
	return &denial{z: z, ap: ap, tr: tr, do: do, seen: map[string]bool{}}
}

func (d *denial) nsec3() bool { return d.ap.NSEC3PARAM != nil && d.ap.NSEC3 != nil }

func (d *denial) add(e *tree.Elem, t uint16) {
	if e == nil || d.seen[e.Name()] {
		return
	}
	rrs := typeFromElem(e, t, d.do)
	if len(rrs) == 0 {
		return
	}
	d.seen[e.Name()] = true
	d.out = append(d.out, rrs...)
}

// nsecAt adds the NSEC owned by name, if there is one.
func (d *denial) nsecAt(name string) {
	if e, ok := d.tr.Search(name); ok {
		d.add(e, dns.TypeNSEC)
	}
}

// nsecCover adds the NSEC that covers name: the one owned by the closest
// name before it that has an NSEC (names below a zone cut, such as glue,
// have none).
func (d *denial) nsecCover(name string) {
	e, ok := d.tr.Prev(name)
	for ok && len(e.Type(dns.TypeNSEC)) == 0 {
		e, ok = d.tr.Before(e.Name())
	}
	if !ok {
		e = d.tr.Max() // the chain wraps around
		for e != nil && len(e.Type(dns.TypeNSEC)) == 0 {
			e, _ = d.tr.Before(e.Name())
		}
	}
	d.add(e, dns.TypeNSEC)
}

func (d *denial) hashed(name string) string {
	p := d.ap.NSEC3PARAM
	return strings.ToLower(dns.HashName(name, p.Hash, p.Iterations, p.Salt)) + "." + d.z.origin
}

// nsec3Match adds the NSEC3 matching name and reports whether there is one.
func (d *denial) nsec3Match(name string) bool {
	e, ok := d.ap.NSEC3.Search(d.hashed(name))
	if ok {
		d.add(e, dns.TypeNSEC3)
	}
	return ok
}

// nsec3Cover adds the NSEC3 covering the hash of name.
func (d *denial) nsec3Cover(name string) {
	e, ok := d.ap.NSEC3.Before(d.hashed(name))
	if !ok {
		e = d.ap.NSEC3.Max() // the chain wraps around
	}
	d.add(e, dns.TypeNSEC3)
}

// nsec3ClosestEncloser adds the closest encloser proof for qname (RFC 5155
// §7.2.1): the NSEC3 matching its closest provable encloser and the one
// covering the next closer name. It returns the closest encloser.
func (d *denial) nsec3ClosestEncloser(qname string) string {
	next := qname
	for ce := parentName(qname); ; ce = parentName(ce) {
		if d.nsec3Match(ce) || ce == d.z.origin || ce == "." {
			d.nsec3Cover(next)
			return ce
		}
		next = ce
	}
}

// noData proves qname exists without the queried type (RFC 4035
// §3.1.3.1, RFC 5155 §7.2.3/§7.2.4), including an empty non-terminal and a
// DS query at an unsigned delegation.
func (d *denial) noData(qname string) {
	if !d.nsec3() {
		if _, ok := d.tr.Search(qname); ok {
			d.nsecAt(qname)
		} else {
			d.nsecCover(qname) // an empty non-terminal has no NSEC of its own
		}
		return
	}
	if !d.nsec3Match(qname) {
		d.nsec3ClosestEncloser(qname) // an Opt-Out delegation (RFC 5155 §7.2.4)
	}
}

// nameError proves qname doesn't exist and no wildcard matches it (RFC
// 4035 §3.1.3.2, RFC 5155 §7.2.2).
func (d *denial) nameError(qname string) {
	if !d.nsec3() {
		d.nsecCover(qname)
		if ce, ok := d.z.ClosestEncloser(qname); ok {
			d.nsecCover("*." + ce.Name())
		}
		return
	}
	ce := d.nsec3ClosestEncloser(qname)
	d.nsec3Cover("*." + ce)
}

// wildcardAnswer proves qname itself doesn't exist, for an answer
// synthesized from the wildcard at *.ce (RFC 4035 §3.1.3.3, RFC 5155
// §7.2.6).
func (d *denial) wildcardAnswer(qname, ce string) {
	if !d.nsec3() {
		d.nsecCover(qname)
		return
	}
	d.nsec3Cover(nextCloser(qname, ce))
}

// wildcardNoData proves qname doesn't exist and the wildcard at *.ce lacks
// the queried type (RFC 4035 §3.1.3.4, RFC 5155 §7.2.5).
func (d *denial) wildcardNoData(qname, ce string) {
	wildcard := "*." + ce
	if !d.nsec3() {
		d.nsecCover(qname)
		d.noData(wildcard)
		return
	}
	d.nsec3Match(ce)
	d.nsec3Cover(nextCloser(qname, ce))
	d.nsec3Match(wildcard)
}

// parentName returns name without its first label.
func parentName(name string) string {
	off, end := dns.NextLabel(name, 0)
	if end {
		return "."
	}
	return name[off:]
}

// nextCloser returns the ancestor of qname one label longer than ce.
func nextCloser(qname, ce string) string {
	n := qname
	for p := parentName(n); p != ce && n != "."; p = parentName(p) {
		n = p
	}
	return n
}
