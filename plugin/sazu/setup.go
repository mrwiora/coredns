package sazu

import (
	"strconv"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/miekg/dns"
)

func init() { plugin.Register("sazu", setup) }

func setup(c *caddy.Controller) error {
	cfg, err := parseSazu(c)
	if err != nil {
		return plugin.Error("sazu", err)
	}

	config := dnsserver.GetConfig(c)
	// UPDATE is rejected with NotImplemented unless a plugin opts a config
	// in -- this is what lets our own UPDATE handling below actually run.
	config.AllowOpcode(dns.OpcodeUpdate)

	capture := NewRawCapture(5*time.Second, 4096)
	// A signed push carrying real RRSIGs routinely exceeds 512 bytes (RFC
	// 1035's plain-DNS-over-UDP ceiling) -- and, worse, often exceeds the
	// ~1472-byte path MTU before IP fragmentation kicks in, which gets
	// silently dropped by many networks/firewalls entirely (found the
	// hard way against a real server). Raising the UDP receive buffer
	// only helped with the first problem, not the second, so sazuctl
	// sends anything of meaningful size over TCP instead -- both
	// listeners share the same capture, since RawCapture keys entries by
	// address + message ID regardless of transport.
	config.UDPDecorateReaderFunc = capture.DecorateReaderFunc
	config.TCPDecorateReaderFunc = capture.DecorateReaderFunc

	validator := NewValidator()
	if cfg.trustAnchorPath != "" {
		anchors, err := LoadTrustAnchors(cfg.trustAnchorPath)
		if err != nil {
			return plugin.Error("sazu", err)
		}
		validator.Anchors = anchors
	}

	s := &Sazu{
		Zones:                       cfg.zones,
		Validator:                   validator,
		Capture:                     capture,
		InsecureSkipChainValidation: cfg.insecureSkipChainValidation,
		RateLimiter:                 NewRateLimiter(cfg.fullPushesPerDay, cfg.keyManagementPushesPerDay),
		IPRateLimiter:               NewIPRateLimiter(cfg.ipUpdatesPerMinute),
		Versions:                    NewVersionRegistry(),
		MaxSIG0Lifetime:             cfg.maxSIG0Lifetime,
	}

	if cfg.dbPath != "" {
		db, err := Open(cfg.dbPath)
		if err != nil {
			return plugin.Error("sazu", err)
		}
		store, keys, contacts, err := db.LoadAll()
		if err != nil {
			db.Close()
			return plugin.Error("sazu", err)
		}
		versions, err := db.LoadVersions()
		if err != nil {
			db.Close()
			return plugin.Error("sazu", err)
		}
		for zone, v := range versions {
			s.Versions.Set(zone, v)
		}
		s.DB = db
		s.Store = store
		s.Keys = keys
		s.Contacts = contacts
		c.OnShutdown(db.Close)
	} else {
		s.Store = NewStore()
		s.Keys = NewKeyRegistry()
		s.Contacts = NewContactRegistry()
	}

	config.AddPlugin(func(next plugin.Handler) plugin.Handler {
		s.Next = next
		return s
	})

	return nil
}

type sazuConfig struct {
	zones                       []string
	insecureSkipChainValidation bool
	dbPath                      string
	fullPushesPerDay            int
	keyManagementPushesPerDay   int
	ipUpdatesPerMinute          int
	maxSIG0Lifetime             time.Duration
	trustAnchorPath             string
}

func parseSazu(c *caddy.Controller) (sazuConfig, error) {
	cfg := sazuConfig{
		fullPushesPerDay:          DefaultFullPushesPerDay,
		keyManagementPushesPerDay: DefaultKeyManagementPushesPerDay,
		ipUpdatesPerMinute:        DefaultIPUpdatesPerMinute,
		maxSIG0Lifetime:           DefaultMaxSIG0Lifetime,
	}
	for c.Next() {
		args := c.RemainingArgs()
		cfg.zones = plugin.OriginsFromArgsOrServerBlock(args, c.ServerBlockKeys)

		for c.NextBlock() {
			// RemainingArgs, not NextArg/c.Val(), for both cases below --
			// the idiomatic way elsewhere in this codebase (see e.g.
			// plugin/hosts/setup.go) to collect a directive's own
			// arguments within a block, and to reject the wrong count.
			switch c.Val() {
			case "insecure_skip_chain_validation":
				if len(c.RemainingArgs()) != 0 {
					return sazuConfig{}, c.ArgErr()
				}
				cfg.insecureSkipChainValidation = true
			case "db":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return sazuConfig{}, c.ArgErr()
				}
				cfg.dbPath = args[0]
			case "rate_limit":
				// §12: <full-pushes-per-day> <key-management-pushes-per-day>,
				// both over a rolling 24h window -- see ratelimit.go.
				// Defaults (5/50) apply if this directive is omitted
				// entirely.
				args := c.RemainingArgs()
				if len(args) != 2 {
					return sazuConfig{}, c.ArgErr()
				}
				full, err := strconv.Atoi(args[0])
				if err != nil || full < 0 {
					return sazuConfig{}, c.Errf("rate_limit: invalid full-pushes-per-day %q", args[0])
				}
				keyMgmt, err := strconv.Atoi(args[1])
				if err != nil || keyMgmt < 0 {
					return sazuConfig{}, c.Errf("rate_limit: invalid key-management-pushes-per-day %q", args[1])
				}
				cfg.fullPushesPerDay = full
				cfg.keyManagementPushesPerDay = keyMgmt
			case "ip_rate_limit":
				// §12: <updates-per-minute>, the global, per-source-IP
				// flood/scan throttle -- see ipratelimit.go. Default (30)
				// applies if this directive is omitted entirely.
				args := c.RemainingArgs()
				if len(args) != 1 {
					return sazuConfig{}, c.ArgErr()
				}
				perMinute, err := strconv.Atoi(args[0])
				if err != nil || perMinute < 0 {
					return sazuConfig{}, c.Errf("ip_rate_limit: invalid updates-per-minute %q", args[0])
				}
				cfg.ipUpdatesPerMinute = perMinute
			case "trust_anchor":
				// A file of root DS/DNSKEY trust anchors replacing the
				// built-in ones -- see LoadTrustAnchors.
				args := c.RemainingArgs()
				if len(args) != 1 {
					return sazuConfig{}, c.ArgErr()
				}
				cfg.trustAnchorPath = args[0]
			case "max_sig0_lifetime":
				// Longest accepted SIG(0) validity window -- see
				// DefaultMaxSIG0Lifetime. Default applies if omitted.
				args := c.RemainingArgs()
				if len(args) != 1 {
					return sazuConfig{}, c.ArgErr()
				}
				d, err := time.ParseDuration(args[0])
				if err != nil || d <= 0 {
					return sazuConfig{}, c.Errf("max_sig0_lifetime: invalid duration %q", args[0])
				}
				cfg.maxSIG0Lifetime = d
			default:
				return sazuConfig{}, c.ArgErr()
			}
		}
	}
	return cfg, nil
}
