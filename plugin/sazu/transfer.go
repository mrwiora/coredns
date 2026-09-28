package sazu

import (
	"strings"

	"github.com/coredns/coredns/plugin/transfer"

	"github.com/miekg/dns"
)

var _ transfer.Transferer = (*Sazu)(nil)

// Transfer implements transfer.Transferer: AXFR, and IXFR by AXFR
// fallback, of an onboarded zone's current data, with the transfer
// plugin's access control. A secondary receives the zone exactly as
// signed by its owner.
func (s *Sazu) Transfer(zone string, serial uint32) (<-chan []dns.RR, error) {
	z, ok := s.Store.Get(strings.ToLower(dns.Fqdn(zone)))
	if !ok {
		return nil, transfer.ErrNotAuthoritative
	}
	view := z.View()
	if view == nil {
		return nil, transfer.ErrNotAuthoritative
	}
	return view.Transfer(serial)
}

// notify sends NOTIFY for zone to the transfer plugin's secondaries in the
// background. Changes that arrive while a NOTIFY is in flight are
// coalesced into one more.
func (s *Sazu) notify(zone string) {
	if s.Xfer == nil {
		return
	}
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	if s.notifying == nil {
		s.notifying = make(map[string]bool)
	}
	if running, ok := s.notifying[zone]; ok {
		if running {
			s.notifying[zone] = false // run once more when done
		}
		return
	}
	s.notifying[zone] = true
	go func() {
		for {
			if err := s.Xfer.Notify(zone); err != nil {
				log.Warningf("notify for %s: %v", zone, err)
			}
			s.notifyMu.Lock()
			if !s.notifying[zone] {
				s.notifying[zone] = true
				s.notifyMu.Unlock()
				continue
			}
			delete(s.notifying, zone)
			s.notifyMu.Unlock()
			return
		}
	}()
}
