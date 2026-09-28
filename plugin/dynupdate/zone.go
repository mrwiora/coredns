package dynupdate

import (
	"errors"
	"fmt"

	"github.com/coredns/coredns/plugin/pkg/rfc2136"

	"github.com/miekg/dns"
)

const (
	allNames = "*"
	allTypes = "*"
)

var errMissingSOA = errors.New("zone has no SOA")

func validateRecords(records []dns.RR, origin string) error {
	origin = canonicalName(origin)
	soaCount := 0
	nameTypes := make(map[string]map[uint16]struct{})
	for _, rr := range records {
		if rr == nil {
			return errors.New("zone contains a nil record")
		}
		h := rr.Header()
		if h.Class != dns.ClassINET {
			return errors.New("zone contains a non-IN record")
		}
		if !inZone(origin, h.Name) {
			return errors.New("zone contains an out-of-zone record")
		}
		if unsupportedRRType(h.Rrtype) {
			return fmt.Errorf("zone contains unsupported RR type %s", dns.TypeToString[h.Rrtype])
		}
		name := canonicalName(h.Name)
		types := nameTypes[name]
		if types == nil {
			types = make(map[uint16]struct{})
			nameTypes[name] = types
		}
		if h.Rrtype == dns.TypeCNAME && len(types) != 0 {
			return fmt.Errorf("zone contains CNAME data conflict at %s", h.Name)
		}
		if h.Rrtype != dns.TypeCNAME {
			if _, exists := types[dns.TypeCNAME]; exists {
				return fmt.Errorf("zone contains CNAME data conflict at %s", h.Name)
			}
		}
		types[h.Rrtype] = struct{}{}
		if h.Rrtype == dns.TypeSOA {
			soa, ok := rr.(*dns.SOA)
			if !ok {
				return errors.New("zone contains an invalid SOA record")
			}
			if canonicalName(h.Name) != origin {
				return errors.New("zone contains a non-apex SOA record")
			}
			// RFC 2136 sections 4.2 and 7.11 prohibit zero for
			// interoperability with older DNS implementations.
			if soa.Serial == 0 {
				return errors.New("zone contains an SOA with serial zero")
			}
			soaCount++
		}
	}
	if soaCount == 0 {
		return errMissingSOA
	}
	if soaCount != 1 {
		return errors.New("zone contains more than one SOA record")
	}
	return nil
}

type permission struct {
	key      string
	name     string
	types    map[uint16]struct{}
	allTypes bool
}

func canonicalName(name string) string {
	return rfc2136.CanonicalName(name)
}

func inZone(origin, name string) bool {
	return rfc2136.InZone(origin, name)
}

func (d *DynUpdate) configuredKey(key string) bool {
	key = canonicalName(key)
	for _, p := range d.permissions {
		if p.key == key {
			return true
		}
	}
	return false
}

func (d *DynUpdate) allows(key, name string, rrType uint16) bool {
	key = canonicalName(key)
	name = canonicalName(name)
	for _, p := range d.permissions {
		if p.key != key || (p.name != allNames && p.name != name) {
			continue
		}
		if p.allTypes {
			return true
		}
		if _, ok := p.types[rrType]; ok {
			return true
		}
	}
	return false
}

func (d *DynUpdate) nameInUse(name string) bool {
	name = canonicalName(name)
	for _, rr := range d.records {
		if canonicalName(rr.Header().Name) == name {
			return true
		}
	}
	return false
}

func (d *DynUpdate) rrset(name string, rrType uint16) []dns.RR {
	return rrsetOf(d.records, name, rrType)
}

func rrsetOf(records []dns.RR, name string, rrType uint16) []dns.RR {
	name = canonicalName(name)
	var set []dns.RR
	for _, rr := range records {
		h := rr.Header()
		if canonicalName(h.Name) == name && h.Rrtype == rrType {
			set = append(set, rr)
		}
	}
	return set
}

func (d *DynUpdate) rrsetExists(name string, rrType uint16) bool {
	return len(d.rrset(name, rrType)) != 0
}

func soaOf(records []dns.RR) *dns.SOA {
	for _, rr := range records {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
}

func soaAt(records []dns.RR, name string) *dns.SOA {
	name = canonicalName(name)
	for _, rr := range records {
		soa, ok := rr.(*dns.SOA)
		if ok && canonicalName(soa.Header().Name) == name {
			return soa
		}
	}
	return nil
}

func cloneRecords(records []dns.RR) []dns.RR {
	cloned := make([]dns.RR, len(records))
	for i, rr := range records {
		cloned[i] = dns.Copy(rr)
	}
	return cloned
}

func sameRR(a, b dns.RR) bool {
	return rfc2136.SameRR(a, b)
}

func findRR(records []dns.RR, want dns.RR) int {
	for i, rr := range records {
		if sameRR(rr, want) {
			return i
		}
	}
	return -1
}

func removeRecords(records []dns.RR, match func(dns.RR) bool) ([]dns.RR, bool) {
	result := make([]dns.RR, 0, len(records))
	changed := false
	for _, rr := range records {
		if match(rr) {
			changed = true
			continue
		}
		result = append(result, rr)
	}
	return result, changed
}

func countRRset(records []dns.RR, name string, rrType uint16) int {
	name = canonicalName(name)
	count := 0
	for _, rr := range records {
		if canonicalName(rr.Header().Name) == name && rr.Header().Rrtype == rrType {
			count++
		}
	}
	return count
}

func hasCNAME(records []dns.RR, name string) bool {
	return countRRset(records, name, dns.TypeCNAME) != 0
}

func hasOtherData(records []dns.RR, name string) bool {
	name = canonicalName(name)
	for _, rr := range records {
		if canonicalName(rr.Header().Name) != name {
			continue
		}
		if !cnameCompatibleType(rr.Header().Rrtype) {
			return true
		}
	}
	return false
}

func cnameCompatibleType(rrType uint16) bool {
	return rfc2136.CNAMECompatible(rrType)
}

func serialGreater(a, b uint32) bool {
	return rfc2136.SerialGreater(a, b)
}

func bumpSerial(records []dns.RR) {
	if soa := soaOf(records); soa != nil {
		soa.Serial++
		// RFC 2136 section 7.11 recommends that an automatically incremented
		// serial never become zero after wrapping at 2^32.
		if soa.Serial == 0 {
			soa.Serial = 1
		}
	}
}

func knownRRType(rrType uint16) bool {
	return rfc2136.KnownType(rrType)
}

func isQueryMetaType(rrType uint16) bool {
	return rfc2136.IsQueryMetaType(rrType)
}
