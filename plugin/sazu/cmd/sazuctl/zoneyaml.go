package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin/sazu"

	"github.com/miekg/dns"
	yaml "go.yaml.in/yaml/v3"
)

// yamlZoneFile is the optional, friendlier alternative to hand-writing a
// BIND-format zone file: fewer places to get a number or an escaping
// rule wrong, and a shape a diff/review tool (or a person who has never
// seen a zone file) can actually make sense of. It is deliberately a
// thin layer over the same content a real zone file carries -- a record
// value is ordinary zone-file syntax for whatever comes after the type
// (see recordLine) -- rather than a new content model of its own: the
// only things it actually simplifies are the two SOA fields that
// consistently confuse people writing one by hand (the serial number,
// and the responsible-party mailbox's dot-for-@ encoding), plus letting
// record names be written relative to the zone the way a real zone file
// already allows.
type yamlZoneFile struct {
	Zone    string       `yaml:"zone"`
	TTL     uint32       `yaml:"ttl"`
	SOA     yamlSOA      `yaml:"soa"`
	Records []yamlRecord `yaml:"records"`
}

type yamlSOA struct {
	NS string `yaml:"ns"`
	// AdminEmail is an ordinary "user@domain" address, converted to the
	// zone file's own dot-separated mailbox encoding (RFC 1035 §8.13) --
	// the more commonly confused of the two fields this format exists to
	// simplify. Mbox is the escape hatch for anyone who'd rather write
	// that encoding directly; give exactly one of the two.
	AdminEmail string `yaml:"admin_email"`
	Mbox       string `yaml:"mbox"`
	// Serial is "auto" (or empty) to fill in today's date as YYYYMMDD00
	// -- the conventional format official documentation recommends, and
	// one less number a person has to get right by hand -- or an
	// explicit decimal number, needed if you push more than once on the
	// same day and want each push to carry a strictly increasing value.
	Serial  string `yaml:"serial"`
	Refresh uint32 `yaml:"refresh"`
	Retry   uint32 `yaml:"retry"`
	Expire  uint32 `yaml:"expire"`
	MinTTL  uint32 `yaml:"minttl"`
}

type yamlRecord struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"`
	// Value is ordinary zone-file syntax for whatever comes after the
	// type in a real zone file line -- e.g. "203.0.113.10" for an A
	// record, "10 mail.example.org." for an MX record, or a quoted
	// string for a TXT record. Reusing that syntax rather than inventing
	// a YAML-native shape per RR type means every record type this tool
	// (or miekg/dns) already understands works here with no extra code.
	Value string `yaml:"value"`
	TTL   uint32 `yaml:"ttl"`
}

// loadZoneSource loads a zone's SOA and other records from path,
// dispatching on its extension: ".yaml"/".yml" through the friendlier
// format above, anything else through sazu.LoadZoneFile exactly as
// before. push-zone calls this instead of sazu.LoadZoneFile directly,
// so a YAML zone definition works as a drop-in -zonefile value with no
// separate conversion step required.
func loadZoneSource(path, zone string) (*dns.SOA, []dns.RR, error) {
	switch strings.ToLower(pathExt(path)) {
	case ".yaml", ".yml":
		return loadYAMLZone(path, zone)
	default:
		return sazu.LoadZoneFile(path, zone)
	}
}

func pathExt(path string) string {
	if i := strings.LastIndexByte(path, '.'); i >= 0 {
		return path[i:]
	}
	return ""
}

// loadYAMLZone reads and converts a YAML zone definition at path. zone
// is used only as a fallback when the file's own top-level "zone" field
// is empty.
func loadYAMLZone(path, zone string) (*dns.SOA, []dns.RR, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var yz yamlZoneFile
	if err := yaml.Unmarshal(data, &yz); err != nil {
		return nil, nil, fmt.Errorf("%s: parsing YAML: %w", path, err)
	}
	soa, rrs, err := yamlZoneToRRs(&yz, zone)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return soa, rrs, nil
}

// yamlZoneToRRs converts a parsed yamlZoneFile into the same (*dns.SOA,
// []dns.RR) shape sazu.LoadZoneFile returns for a real zone file.
// fallbackZone is used only when yz.Zone is empty.
func yamlZoneToRRs(yz *yamlZoneFile, fallbackZone string) (*dns.SOA, []dns.RR, error) {
	zone := yz.Zone
	if zone == "" {
		zone = fallbackZone
	}
	if zone == "" {
		return nil, nil, fmt.Errorf("no zone given (neither the YAML file's own \"zone\" field nor -zone)")
	}
	zone = dns.Fqdn(zone)

	ttl := yz.TTL
	if ttl == 0 {
		ttl = 3600
	}

	mbox := strings.TrimSpace(yz.SOA.Mbox)
	if mbox == "" {
		if yz.SOA.AdminEmail == "" {
			return nil, nil, fmt.Errorf("soa.admin_email or soa.mbox is required")
		}
		m, err := emailToMbox(yz.SOA.AdminEmail)
		if err != nil {
			return nil, nil, fmt.Errorf("soa.admin_email: %w", err)
		}
		mbox = m
	} else {
		mbox = dns.Fqdn(mbox)
	}

	if yz.SOA.NS == "" {
		return nil, nil, fmt.Errorf("soa.ns is required")
	}

	serial, err := resolveSerial(yz.SOA.Serial)
	if err != nil {
		return nil, nil, fmt.Errorf("soa.serial: %w", err)
	}

	soaLine := fmt.Sprintf("%s %d IN SOA %s %s %d %d %d %d %d",
		zone, ttl, dns.Fqdn(yz.SOA.NS), mbox, serial,
		orDefault(yz.SOA.Refresh, 3600), orDefault(yz.SOA.Retry, 900),
		orDefault(yz.SOA.Expire, 604800), orDefault(yz.SOA.MinTTL, ttl))
	soaRR, err := dns.NewRR(soaLine)
	if err != nil {
		return nil, nil, fmt.Errorf("building SOA record: %w", err)
	}
	soa, ok := soaRR.(*dns.SOA)
	if !ok {
		return nil, nil, fmt.Errorf("internal error: SOA line parsed as %T", soaRR)
	}

	rrs := make([]dns.RR, 0, len(yz.Records))
	for i, rec := range yz.Records {
		if rec.Type == "" || rec.Value == "" {
			return nil, nil, fmt.Errorf("record %d (name %q): type and value are required", i, rec.Name)
		}
		name := recordOwnerName(rec.Name, zone)
		rttl := rec.TTL
		if rttl == 0 {
			rttl = ttl
		}
		line := fmt.Sprintf("%s %d IN %s %s", name, rttl, strings.ToUpper(rec.Type), rec.Value)
		rr, err := dns.NewRR(line)
		if err != nil {
			return nil, nil, fmt.Errorf("record %d (name %q, type %q): %w", i, rec.Name, rec.Type, err)
		}
		rrs = append(rrs, rr)
	}
	return soa, rrs, nil
}

// recordOwnerName resolves a YAML record's "name" field the same way a
// real zone file resolves an unqualified name: "@" (or empty) means the
// zone apex itself; a name with a trailing dot is absolute and used as
// given; anything else is relative to zone.
func recordOwnerName(name, zone string) string {
	switch name {
	case "@", "":
		return zone
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "." + zone
}

// emailToMbox converts an ordinary "local@domain" address into the SOA
// RNAME encoding RFC 1035 §8.13 actually uses: the "@" becomes a ".",
// and any literal "." already in the local part is escaped so it isn't
// mistaken for that separator -- the single most common way a
// hand-written zone file's SOA line is subtly wrong.
func emailToMbox(email string) (string, error) {
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return "", fmt.Errorf("invalid email address %q: expected \"local@domain\"", email)
	}
	local, domain := email[:at], email[at+1:]
	local = strings.ReplaceAll(local, ".", `\.`)
	return dns.Fqdn(local + "." + domain), nil
}

// resolveSerial interprets a YAML soa.serial value: "auto" or empty
// fills in today's date (UTC) as YYYYMMDD00, the conventional format;
// anything else must parse as a plain uint32.
func resolveSerial(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "auto") {
		return dateSerial(time.Now().UTC()), nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%q: must be \"auto\" or a number: %w", s, err)
	}
	return uint32(n), nil
}

// dateSerial computes the YYYYMMDD00 conventional serial for t. Always
// ends in "00" -- this tool has no state across invocations to track
// "how many times already today," so a second push on the same day
// needs an explicit soa.serial to get a strictly increasing value; see
// resolveSerial's own doc comment.
func dateSerial(t time.Time) uint32 {
	return uint32(t.Year())*1000000 + uint32(t.Month())*10000 + uint32(t.Day())*100
}

func orDefault(v, def uint32) uint32 {
	if v == 0 {
		return def
	}
	return v
}
