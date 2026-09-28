package sazu

import (
	"path/filepath"
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

	// SIG(0) is verified over the exact bytes the client sent.
	config.CaptureRawRequests(dns.OpcodeUpdate)

	cfg.dbPath = underRoot(config.Root, cfg.dbPath)
	cfg.trustAnchorPath = underRoot(config.Root, cfg.trustAnchorPath)

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
		InsecureSkipChainValidation: cfg.insecureSkipChainValidation,
		RateLimiter:                 NewRateLimiter(cfg.fullPushesPerDay, cfg.keyManagementPushesPerDay),
		IPRateLimiter:               NewIPRateLimiter(cfg.ipUpdatesPerMinute),
		Versions:                    NewVersionRegistry(),
		Pending:                     NewPendingRollovers(),
		RolloverHoldDown:            cfg.rolloverHoldDown,
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
		pending, err := db.LoadPendingRollovers()
		if err != nil {
			db.Close()
			return plugin.Error("sazu", err)
		}
		for zone, pr := range pending {
			s.Pending.Set(zone, pr)
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
	rolloverHoldDown            time.Duration
}

func parseSazu(c *caddy.Controller) (sazuConfig, error) {
	cfg := sazuConfig{
		fullPushesPerDay:          DefaultFullPushesPerDay,
		keyManagementPushesPerDay: DefaultKeyManagementPushesPerDay,
		ipUpdatesPerMinute:        DefaultIPUpdatesPerMinute,
		maxSIG0Lifetime:           DefaultMaxSIG0Lifetime,
		rolloverHoldDown:          DefaultRolloverHoldDown,
	}
	seen := false
	for c.Next() {
		if seen {
			return sazuConfig{}, plugin.ErrOnce
		}
		seen = true
		args := c.RemainingArgs()
		cfg.zones = plugin.OriginsFromArgsOrServerBlock(args, c.ServerBlockKeys)

		for c.NextBlock() {
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
				// §11.2: <full-pushes-per-day> <key-management-pushes-per-day>,
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
				// §11.2: <updates-per-minute>, the global, per-source-IP
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
			case "rollover_hold_down":
				// How long a KSK rollover not co-signed by the old KSK
				// waits -- see rollover.go. 0 disables the hold-down.
				args := c.RemainingArgs()
				if len(args) != 1 {
					return sazuConfig{}, c.ArgErr()
				}
				d, err := time.ParseDuration(args[0])
				if err != nil || d < 0 {
					return sazuConfig{}, c.Errf("rollover_hold_down: invalid duration %q", args[0])
				}
				cfg.rolloverHoldDown = d
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
				return sazuConfig{}, c.Errf("unknown property %q", c.Val())
			}
		}
	}
	return cfg, nil
}

// underRoot resolves a relative path below the root plugin's directory,
// as other plugins' file arguments are.
func underRoot(root, path string) string {
	if path == "" || filepath.IsAbs(path) || root == "" {
		return path
	}
	return filepath.Join(root, path)
}
