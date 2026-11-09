package nc

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// ListenSettings choose where DNS is served.
//
//	mode "all":      every address of the server (":port")
//	mode "selected": all addresses of the chosen interfaces plus the
//	                 individually chosen addresses
//
// Without a saved setting, NC_DNS_LISTEN from the environment is used.
type ListenSettings struct {
	Mode       string   `json:"mode"`
	Interfaces []string `json:"interfaces"`
	Addresses  []string `json:"addresses"`
	Port       int      `json:"port"`
}

func (a *App) listenSettings(ctx context.Context) (ListenSettings, bool) {
	var s ListenSettings
	found, err := a.getSetting(ctx, "dns.listen", &s)
	if err != nil {
		log.Printf("settings: %v", err)
	}
	if !found || err != nil {
		return ListenSettings{}, false
	}
	return s, true
}

// listenAddrs turns settings into host:port strings.
func listenAddrs(s ListenSettings) ([]string, error) {
	if s.Port < 1 || s.Port > 65535 {
		return nil, errors.New("port must be between 1 and 65535")
	}
	port := strconv.Itoa(s.Port)
	switch s.Mode {
	case "all":
		return []string{net.JoinHostPort("", port)}, nil
	case "selected":
	default:
		return nil, errors.New(`mode must be "all" or "selected"`)
	}
	seen := map[netip.Addr]bool{}
	var ips []netip.Addr
	add := func(ip netip.Addr) {
		if !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	for _, name := range s.Interfaces {
		got, err := ifaceIPs(name)
		if err != nil {
			return nil, fmt.Errorf("interface %s: %w", name, err)
		}
		if len(got) == 0 {
			return nil, fmt.Errorf("interface %s has no usable IP address", name)
		}
		for _, ip := range got {
			add(ip)
		}
	}
	for _, raw := range s.Addresses {
		ip, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address", raw)
		}
		add(ip.Unmap())
	}
	if len(ips) == 0 {
		return nil, errors.New("choose at least one interface or address")
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Less(ips[j]) })
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = net.JoinHostPort(ip.String(), port)
	}
	return out, nil
}

// desiredListen returns the addresses DNS should listen on now.
func (a *App) desiredListen(ctx context.Context) ([]string, error) {
	if s, ok := a.listenSettings(ctx); ok {
		return listenAddrs(s)
	}
	return a.cfg.DNSListen, nil
}

// startDNS binds the configured addresses. If a saved setting cannot be
// bound (for example an IP has gone), it falls back to NC_DNS_LISTEN so the
// server keeps answering.
func (a *App) startDNS(ctx context.Context) error {
	addrs, err := a.desiredListen(ctx)
	if err == nil {
		if err = a.dns.Listen(addrs); err == nil {
			return nil
		}
	}
	log.Printf("dns: configured listen addresses unusable (%v); falling back to NC_DNS_LISTEN %v", err, a.cfg.DNSListen)
	return a.dns.Listen(a.cfg.DNSListen)
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		if !m[x] {
			return false
		}
	}
	return true
}

// listenWatcher re-binds when the addresses of selected interfaces change
// (for example a new anycast address is added to anycast0).
func (a *App) listenWatcher(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		want, err := a.desiredListen(ctx)
		if err != nil || sameSet(want, a.dns.Addrs()) {
			continue
		}
		if err := a.dns.Listen(want); err != nil {
			log.Printf("dns: interface addresses changed but rebinding failed: %v", err)
		} else if err := a.applyDoT(ctx); err != nil {
			log.Printf("dns: DNS over TLS not moved to the new addresses: %v", err)
		}
	}
}

func (a *App) getListen(c *fiber.Ctx) error {
	ifs, err := listInterfaces()
	if err != nil {
		return err
	}
	s, saved := a.listenSettings(c.UserContext())
	if !saved {
		s = ListenSettings{Mode: "all", Port: 53}
	}
	if s.Interfaces == nil {
		s.Interfaces = []string{}
	}
	if s.Addresses == nil {
		s.Addresses = []string{}
	}
	return c.JSON(fiber.Map{"settings": s, "saved": saved, "active": a.dns.Addrs(), "env_default": a.cfg.DNSListen, "interfaces": ifs})
}

func (a *App) updateListen(c *fiber.Ctx) error {
	var s ListenSettings
	if err := c.BodyParser(&s); err != nil {
		return bad(c, "invalid body")
	}
	if s.Port == 0 {
		s.Port = 53
	}
	addrs, err := listenAddrs(s)
	if err != nil {
		return bad(c, err.Error())
	}
	if err := a.dns.Listen(addrs); err != nil {
		return bad(c, "could not listen there (previous addresses kept): "+err.Error())
	}
	if err := a.putSetting(c.UserContext(), "dns.listen", s); err != nil {
		return err
	}
	if err := a.applyDoT(c.UserContext()); err != nil {
		log.Printf("dns: DNS over TLS not moved to the new addresses: %v", err)
	}
	a.auth.AuditC(c, "dns.listen_changed", "", fiber.Map{"settings": s, "addresses": addrs})
	return c.JSON(fiber.Map{"settings": s, "active": a.dns.Addrs()})
}
