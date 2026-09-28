package sazu

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// checkZoneContent checks a full push's records against the rules every
// zone has to follow, which a signature can't vouch for:
//
//   - all records of an RRset share one TTL (RFC 2181 §5.2);
//   - a name with a CNAME has no other data but its RRSIGs and NSEC
//     (RFC 2181 §10.1, RFC 4035 §2.5), and only one CNAME;
//   - a name has at most one DNAME, and no names below it (RFC 6672 §2.4).
//
// ops is the push's update section; only class-zclass adds are checked.
func checkZoneContent(ops []dns.RR, zclass uint16) error {
	ttls := map[rrsetKey]uint32{}
	types := map[string]map[uint16]int{}
	var dnames []string
	for _, rr := range ops {
		h := rr.Header()
		if h.Class != zclass || h.Rrtype == dns.TypeRRSIG {
			continue
		}
		name := strings.ToLower(dns.Fqdn(h.Name))
		k := rrsetKey{name: name, rtype: h.Rrtype}
		if ttl, seen := ttls[k]; seen && ttl != h.Ttl {
			return fmt.Errorf("%s/%s: records of one RRset have different TTLs (RFC 2181 §5.2)", name, dns.TypeToString[h.Rrtype])
		}
		ttls[k] = h.Ttl
		if types[name] == nil {
			types[name] = map[uint16]int{}
		}
		types[name][h.Rrtype]++
		if h.Rrtype == dns.TypeDNAME {
			dnames = append(dnames, name)
		}
	}
	for name, byType := range types {
		if n := byType[dns.TypeCNAME]; n > 0 {
			if n > 1 {
				return fmt.Errorf("%s: more than one CNAME (RFC 2181 §10.1)", name)
			}
			for t := range byType {
				if t != dns.TypeCNAME && t != dns.TypeNSEC {
					return fmt.Errorf("%s: CNAME and %s at the same name (RFC 2181 §10.1)", name, dns.TypeToString[t])
				}
			}
		}
		if byType[dns.TypeDNAME] > 1 {
			return fmt.Errorf("%s: more than one DNAME (RFC 6672 §2.4)", name)
		}
	}
	for _, d := range dnames {
		for name := range types {
			if name != d && dns.IsSubDomain(d, name) {
				return fmt.Errorf("%s: name below the DNAME at %s (RFC 6672 §2.4)", name, d)
			}
		}
	}
	return nil
}
