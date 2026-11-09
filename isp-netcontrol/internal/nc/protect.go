package nc

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/justinthoms/my-dns/isp-netcontrol/internal/dnsserver"
)

// ProtectionSettings are the resolver's defences, as edited in the console.
type ProtectionSettings struct {
	RateLimitEnabled bool     `json:"rate_limit_enabled"`
	RateLimit        int      `json:"rate_limit"` // queries per second per client address
	Burst            int      `json:"burst"`
	Exempt           []string `json:"exempt"` // networks never rate limited
	MinimalANY       bool     `json:"minimal_any"`
	TortureEnabled   bool     `json:"torture_enabled"`
	TortureThreshold int      `json:"torture_threshold"` // NXDOMAIN per domain per minute
	TortureLimit     int      `json:"torture_limit"`     // uncached lookups per second while suspected
	TortureHoldMin   int      `json:"torture_hold_minutes"`
}

func defaultProtectionSettings() ProtectionSettings {
	d := dnsserver.DefaultProtection()
	return ProtectionSettings{RateLimitEnabled: true, RateLimit: d.RateLimit, Burst: d.Burst, Exempt: []string{},
		MinimalANY: d.MinimalANY, TortureEnabled: true, TortureThreshold: d.TortureThreshold,
		TortureLimit: d.TortureLimit, TortureHoldMin: int(d.TortureHold / time.Minute)}
}

// Validate checks the settings and normalises the exempt networks.
func (s *ProtectionSettings) Validate() error {
	if s.RateLimit < 10 || s.RateLimit > 100000 {
		return errors.New("the rate limit must be between 10 and 100,000 queries per second")
	}
	if s.Burst < s.RateLimit || s.Burst > 1000000 {
		return errors.New("the burst must be at least the rate limit (and at most 1,000,000)")
	}
	if s.Exempt == nil {
		s.Exempt = []string{}
	}
	for i, e := range s.Exempt {
		e = strings.TrimSpace(e)
		if !strings.Contains(e, "/") {
			if a, err := netip.ParseAddr(e); err == nil {
				e = netip.PrefixFrom(a, a.BitLen()).String()
			}
		}
		pfx, err := netip.ParsePrefix(e)
		if err != nil {
			return fmt.Errorf("exempt network %q is not an address or network (e.g. 100.64.0.1 or 10.0.0.0/8)", s.Exempt[i])
		}
		s.Exempt[i] = pfx.Masked().String()
	}
	if s.TortureThreshold < 50 || s.TortureThreshold > 1000000 {
		return errors.New("the attack threshold must be between 50 and 1,000,000 NXDOMAIN answers per minute")
	}
	if s.TortureLimit < 1 || s.TortureLimit > 10000 {
		return errors.New("lookups allowed during an attack must be between 1 and 10,000 per second")
	}
	if s.TortureHoldMin < 1 || s.TortureHoldMin > 1440 {
		return errors.New("the attack hold time must be between 1 and 1440 minutes")
	}
	return nil
}

func (a *App) protectionSettings(ctx context.Context) ProtectionSettings {
	s := defaultProtectionSettings()
	if _, err := a.getSetting(ctx, "protection", &s); err != nil {
		log.Printf("settings: %v", err)
	}
	if err := s.Validate(); err != nil {
		log.Printf("protection settings invalid (%v); using defaults", err)
		s = defaultProtectionSettings()
	}
	return s
}

// protection converts the settings for the resolver.
func (s ProtectionSettings) protection() dnsserver.Protection {
	p := dnsserver.Protection{MinimalANY: s.MinimalANY}
	if s.RateLimitEnabled {
		p.RateLimit, p.Burst = s.RateLimit, s.Burst
		for _, e := range s.Exempt {
			p.RateLimitExempt = append(p.RateLimitExempt, netip.MustParsePrefix(e))
		}
	}
	if s.TortureEnabled {
		p.TortureThreshold, p.TortureLimit = s.TortureThreshold, s.TortureLimit
		p.TortureHold = time.Duration(s.TortureHoldMin) * time.Minute
	}
	return p
}

// getProtection returns the settings and what the defences are doing now.
func (a *App) getProtection(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"settings": a.protectionSettings(c.UserContext()), "status": a.dns.ProtectionStatus()})
}

func (a *App) updateProtection(c *fiber.Ctx) error {
	var s ProtectionSettings
	if err := c.BodyParser(&s); err != nil {
		return bad(c, "invalid body")
	}
	if err := s.Validate(); err != nil {
		return bad(c, err.Error())
	}
	if err := a.putSetting(c.UserContext(), "protection", s); err != nil {
		return err
	}
	if err := a.reloadDNS(c.UserContext()); err != nil {
		return err
	}
	a.auth.AuditC(c, "dns.protection_changed", "", s)
	return c.JSON(s)
}
