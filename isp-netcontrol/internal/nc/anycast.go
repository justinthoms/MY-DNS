package nc

import (
	"context"
	"errors"
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/justinthoms/my-dns/isp-netcontrol/internal/anycast"
	"github.com/justinthoms/my-dns/shared/authkit"
)

// AnycastSettings is stored as the "anycast" setting.
type AnycastSettings struct {
	anycast.Config
	CheckName string `json:"check_name"` // name resolved by the health check
}

func defaultAnycastSettings() AnycastSettings {
	return AnycastSettings{Config: anycast.Defaults(), CheckName: "example.com"}
}

func (a *App) anycastSettings(ctx context.Context) AnycastSettings {
	s := defaultAnycastSettings()
	if _, err := a.getSetting(ctx, "anycast", &s); err != nil {
		log.Printf("settings: %v", err)
	}
	return s
}

// checkAnycastInterface refuses interfaces whose withdrawal would cut the
// server off: loopback, container interfaces and the default route.
func checkAnycastInterface(name string) error {
	ifs, err := listInterfaces()
	if err != nil {
		return err
	}
	for _, it := range ifs {
		if it.Name != name {
			continue
		}
		switch {
		case it.Loopback:
			return errors.New("the loopback interface cannot be used for anycast control")
		case it.Internal:
			return errors.New(name + " is a container/bridge interface")
		case it.DefaultRoute:
			return errors.New(name + " carries the default route: taking it down would cut this server off. Put the anycast addresses on a dedicated interface (e.g. a dummy interface anycast0)")
		}
		return nil
	}
	return errors.New("interface " + name + " does not exist")
}

func (a *App) newAnycastMonitor() *anycast.Monitor {
	probe := func(ctx context.Context) error {
		return a.dns.Probe(ctx, a.anycastSettings(ctx).CheckName)
	}
	notify := func(kind, msg string) {
		authkit.Audit(context.Background(), a.db, "system", "anycast."+kind, a.anycastSettings(context.Background()).Interface, map[string]string{"message": msg}, "")
	}
	return anycast.New(anycast.SysLink{}, probe, notify)
}

// startAnycast loads the saved configuration and runs the monitor. The
// returned channel closes when the monitor has stopped (after withdrawing
// the routes on shutdown).
func (a *App) startAnycast(ctx context.Context) <-chan struct{} {
	s := a.anycastSettings(ctx)
	if s.Enabled {
		if err := checkAnycastInterface(s.Interface); err != nil {
			log.Printf("anycast: saved configuration not applied: %v", err)
			s.Enabled = false
		}
	}
	if err := a.anycast.Configure(s.Config); err != nil {
		log.Printf("anycast: %v", err)
	}
	done := make(chan struct{})
	go func() { a.anycast.Run(ctx); close(done) }()
	return done
}

func (a *App) getAnycast(c *fiber.Ctx) error {
	ifs, err := listInterfaces()
	if err != nil {
		return err
	}
	s := a.anycastSettings(c.UserContext())
	return c.JSON(fiber.Map{"settings": s, "status": a.anycast.Status(), "interfaces": ifs})
}

func (a *App) updateAnycast(c *fiber.Ctx) error {
	var s AnycastSettings
	if err := c.BodyParser(&s); err != nil {
		return bad(c, "invalid body")
	}
	s.Interface = strings.TrimSpace(s.Interface)
	if _, err := normaliseDomain(s.CheckName); err != nil {
		return bad(c, "health-check name: "+err.Error())
	}
	if err := s.Config.Validate(); err != nil {
		return bad(c, err.Error())
	}
	if s.Enabled {
		if err := checkAnycastInterface(s.Interface); err != nil {
			return bad(c, err.Error())
		}
	}
	if err := a.putSetting(c.UserContext(), "anycast", s); err != nil {
		return err
	}
	if err := a.anycast.Configure(s.Config); err != nil {
		return bad(c, err.Error())
	}
	a.auth.AuditC(c, "anycast.settings_changed", s.Interface, s)
	return c.JSON(fiber.Map{"settings": s, "status": a.anycast.Status()})
}
