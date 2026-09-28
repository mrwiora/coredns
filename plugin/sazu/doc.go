// Package sazu implements SAZU (Self-Authenticated Zone Update): an
// authoritative DNS server for zones whose owners sign them themselves.
// The owner's signer holds every private key; this server accepts only
// already-signed zone content, carried in RFC 2136 UPDATE messages and
// authenticated with SIG(0) (RFC 2931) by the zone's own DNSSEC keys, and
// it never signs anything. See the protocol specification (readme.md in
// github.com/mrwiora/sazu). Registered as a CoreDNS plugin (plugin.cfg,
// setup.go): `sazu ZONES...` in a Corefile.
package sazu
