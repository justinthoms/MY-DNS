// Package nc wires ISP NetControl together: configuration, database, the
// console API, the DNS server, the firewall and license enforcement.
package nc

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/justinthoms/my-dns/isp-netcontrol/internal/anycast"
	"github.com/justinthoms/my-dns/isp-netcontrol/internal/dnsserver"
	"github.com/justinthoms/my-dns/isp-netcontrol/internal/firewall"
	"github.com/justinthoms/my-dns/isp-netcontrol/internal/license"
	"github.com/justinthoms/my-dns/shared/authkit"
)

// Version is the product version reported to the License Manager.
const Version = "1.3.1"

// Config is read from the environment (see deploy/.env.example).
type Config struct {
	DatabaseURL       string
	MasterKey         string
	HTTPAddr          string
	DNSListen         []string
	StateDir          string
	MachineIDPath     string
	ProductUUIDPath   string
	FirewallEnabled   bool
	NFTPath           string
	LMURL             string
	LMCAFile          string
	SyncInterval      time.Duration
	CookieSecure      bool
	RequireTOTP       bool
	BootstrapEmail    string
	BootstrapPassword string
	TrustedProxies    []string
	QueryLogDays      int
	CacheSize         int
	TLSDir            string // console certificate, also used for DNS over TLS
	DoTPort           int    // DNS over TLS port (default 853)

	// trustedPEM replaces the built-in signing keys. It is unexported on
	// purpose: only this package's tests can set it, never the environment.
	trustedPEM string
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// ConfigFromEnv loads and validates configuration.
func ConfigFromEnv() (Config, error) {
	c := Config{
		DatabaseURL:       env("NC_DATABASE_URL", ""),
		MasterKey:         env("NC_MASTER_KEY", ""),
		HTTPAddr:          env("NC_HTTP_ADDR", "127.0.0.1:8081"),
		DNSListen:         strings.Split(env("NC_DNS_LISTEN", ":53"), ","),
		StateDir:          env("NC_STATE_DIR", "/var/lib/isp-netcontrol"),
		MachineIDPath:     env("NC_MACHINE_ID_PATH", "/etc/machine-id"),
		ProductUUIDPath:   env("NC_PRODUCT_UUID_PATH", "/sys/class/dmi/id/product_uuid"),
		FirewallEnabled:   env("NC_FIREWALL_ENABLED", "true") != "false",
		NFTPath:           env("NC_NFT_PATH", "nft"),
		LMURL:             env("NC_LM_URL", ""),
		LMCAFile:          env("NC_LM_CA_FILE", ""),
		CookieSecure:      env("NC_COOKIE_SECURE", "true") != "false",
		RequireTOTP:       env("NC_REQUIRE_TOTP", "true") != "false",
		BootstrapEmail:    env("NC_BOOTSTRAP_ADMIN_EMAIL", ""),
		BootstrapPassword: env("NC_BOOTSTRAP_ADMIN_PASSWORD", ""),
		TrustedProxies:    strings.Split(env("NC_TRUSTED_PROXIES", "127.0.0.1,::1"), ","),
		TLSDir:            env("NC_TLS_DIR", "/etc/isp-netcontrol/tls"),
	}
	var err error
	if c.SyncInterval, err = time.ParseDuration(env("NC_SYNC_INTERVAL", "6h")); err != nil || c.SyncInterval < time.Second {
		return c, errors.New("NC_SYNC_INTERVAL must be a duration such as 6h")
	}
	if _, err := fmt.Sscan(env("NC_QUERY_LOG_DAYS", "7"), &c.QueryLogDays); err != nil || c.QueryLogDays < 1 {
		return c, errors.New("NC_QUERY_LOG_DAYS must be a positive number")
	}
	if _, err := fmt.Sscan(env("NC_CACHE_SIZE", "100000"), &c.CacheSize); err != nil || c.CacheSize < 1000 {
		return c, errors.New("NC_CACHE_SIZE must be a number of answers, at least 1000")
	}
	if _, err := fmt.Sscan(env("NC_DOT_PORT", "853"), &c.DoTPort); err != nil || c.DoTPort < 1 || c.DoTPort > 65535 {
		return c, errors.New("NC_DOT_PORT must be a port number")
	}
	if v := env("NC_DEFAULT_UPSTREAMS", ""); v != "" {
		ds := DNSSettings{Upstreams: strings.Split(v, ","), BlockMode: "nxdomain", SinkholeV4: "0.0.0.0", SinkholeV6: "::", AllowedClients: []string{"127.0.0.0/8"}}
		if err := ds.Validate(); err != nil {
			return c, fmt.Errorf("NC_DEFAULT_UPSTREAMS: %w", err)
		}
		defaultUpstreams = ds.Upstreams
	}
	if c.DatabaseURL == "" {
		return c, errors.New("NC_DATABASE_URL is required")
	}
	if c.MasterKey == "" {
		return c, errors.New("NC_MASTER_KEY is required")
	}
	return c, nil
}

// App is a running ISP NetControl instance.
type App struct {
	cfg   Config
	db    *pgxpool.Pool
	auth  *authkit.Auth
	lic   *license.Manager
	dns   *dnsserver.Server
	fw    *firewall.Manager
	web   *fiber.App
	certs *certStore

	applyMu  sync.Mutex
	fwStatus fwState

	enforceMu sync.Mutex
	enforced  string // license mode + features last enforced

	stats statsRecorder

	anycast *anycast.Monitor
}

type fwState struct {
	Applied   bool      `json:"applied"`
	Rules     int       `json:"rules"`
	Error     string    `json:"error,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// New connects, migrates and prepares every component (nothing listens yet).
func New(ctx context.Context, cfg Config) (*App, error) {
	box, err := authkit.NewSecretBox(cfg.MasterKey)
	if err != nil {
		return nil, fmt.Errorf("NC_MASTER_KEY: %w", err)
	}
	db, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	if err := waitForDB(ctx, db); err != nil {
		return nil, err
	}
	a := &App{cfg: cfg, db: db, fw: &firewall.Manager{NFT: cfg.NFTPath, Enabled: cfg.FirewallEnabled}, certs: &certStore{dir: cfg.TLSDir}}
	if err := a.migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	a.auth = &authkit.Auth{DB: db, Box: box, Issuer: "ISP NetControl", CookieName: "nc_session",
		Secure: cfg.CookieSecure, RequireTOTP: cfg.RequireTOTP}
	if err := a.auth.EnsureBootstrapAdmin(ctx, cfg.BootstrapEmail, cfg.BootstrapPassword); err != nil {
		return nil, err
	}
	hwid, err := license.HardwareID(license.HardwareSources{MachineIDPath: cfg.MachineIDPath, ProductUUIDPath: cfg.ProductUUIDPath})
	if err != nil {
		return nil, fmt.Errorf("hardware ID: %w", err)
	}
	a.lic, err = license.New(ctx, license.Options{
		DB: db, StateDir: cfg.StateDir, Secret: cfg.MasterKey, HardwareID: hwid, LMCAFile: cfg.LMCAFile,
		TrustedPEM: cfg.trustedPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("license: %w", err)
	}
	pol, err := a.buildPolicy(ctx, a.lic.Current())
	if err != nil {
		return nil, err
	}
	var dnsOpts []dnsserver.Option
	if cfg.CacheSize > 0 {
		dnsOpts = append(dnsOpts, dnsserver.WithCacheSize(cfg.CacheSize))
	}
	a.dns = dnsserver.New(pol, dnsOpts...)
	a.anycast = a.newAnycastMonitor()
	a.web = a.routes()
	return a, nil
}

func waitForDB(ctx context.Context, db *pgxpool.Pool) error {
	var err error
	for i := 0; i < 30; i++ {
		if err = db.Ping(ctx); err == nil {
			return nil
		}
		log.Printf("waiting for database: %v", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("database not reachable: %w", err)
}

func (a *App) migrate(ctx context.Context) error {
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, sql := range []string{`SELECT pg_advisory_xact_lock(7271002)`, authkit.Schema, license.Schema, schemaSQL} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Run serves DNS and HTTP and runs background jobs until ctx is cancelled.
func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a.applyEnforcement(ctx, a.lic.Current())

	if err := a.startDNS(ctx); err != nil {
		return err
	}
	if err := a.applyDoT(ctx); err != nil {
		log.Printf("dns: DNS over TLS not started: %v", err)
	}
	errc := make(chan error, 1)
	go func() {
		log.Printf("console API listening on %s", a.cfg.HTTPAddr)
		errc <- a.web.Listen(a.cfg.HTTPAddr)
	}()
	go a.lic.Run(ctx, a.cfg.SyncInterval, a.syncSettings, func(license.State) {
		if _, err := a.refreshLicense(ctx); err != nil {
			log.Printf("license: %v", err)
		}
	})
	go a.queryLogWriter(ctx)
	go a.statsWriter(ctx)
	go a.sourceRefresher(ctx)
	go a.listenWatcher(ctx)
	anycastDone := a.startAnycast(ctx)

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	cancel()
	// Let the anycast monitor withdraw the routes before DNS stops.
	select {
	case <-anycastDone:
	case <-time.After(3 * time.Second):
	}
	_ = a.web.Shutdown()
	a.dns.Shutdown()
	return runErr
}

// Close releases the database.
func (a *App) Close() { a.db.Close() }

func (a *App) routes() *fiber.App {
	app := fiber.New(fiber.Config{
		AppName:                 "isp-netcontrol",
		DisableStartupMessage:   true,
		BodyLimit:               8 * 1024 * 1024, // block-list imports
		ProxyHeader:             "X-Real-IP",
		EnableTrustedProxyCheck: true,
		TrustedProxies:          a.cfg.TrustedProxies,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			var fe *fiber.Error
			if errors.As(err, &fe) {
				return authkit.APIError(c, fe.Code, "error", fe.Message)
			}
			log.Printf("%s %s: %v", c.Method(), c.Path(), err)
			return authkit.APIError(c, fiber.StatusInternalServerError, "internal", "internal error")
		},
	})
	app.Use(recover.New())
	app.Use(func(c *fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("Cache-Control", "no-store")
		return c.Next()
	})
	app.Get("/healthz", func(c *fiber.Ctx) error {
		if err := a.db.Ping(c.UserContext()); err != nil {
			return authkit.APIError(c, fiber.StatusServiceUnavailable, "db", "database unavailable")
		}
		st, err := a.refreshLicense(c.UserContext())
		if err != nil {
			return err
		}
		return c.JSON(fiber.Map{"ok": true, "license_mode": st.Mode})
	})
	// DNS over HTTPS for subscribers (no session; access list and protection apply).
	app.Get("/dns-query", a.dohQuery)
	app.Post("/dns-query", a.dohQuery)
	api := app.Group("/api", a.auth.OriginGuard())
	a.auth.Mount(api.Group("/auth"))
	p := api.Group("", a.auth.Require())
	p.Get("/status", a.status)
	a.auth.MountAdmins(p.Group("/admins"))
	p.Get("/audit", a.listAudit)

	p.Get("/license", a.getLicense)
	p.Post("/license/activate", a.activateOnline)
	p.Post("/license/upload", a.uploadLicense)
	p.Post("/license/sync", a.syncNow)
	p.Put("/license/settings", a.updateLicenseSettings)

	p.Get("/dns/settings", a.getDNSSettings)
	p.Get("/anycast", a.getAnycast)
	p.Put("/anycast", a.updateAnycast)
	p.Get("/dns/listen", a.getListen)
	p.Put("/dns/listen", a.updateListen)
	p.Put("/dns/settings", a.updateDNSSettings)
	p.Get("/dns/encrypted", a.getEncrypted)
	p.Put("/dns/encrypted", a.updateEncrypted)
	p.Get("/dns/protection", a.getProtection)
	p.Put("/dns/protection", a.updateProtection)
	p.Get("/dns/stats", a.dnsStats)
	p.Get("/dns/timeseries", a.timeseries)
	p.Get("/dns/breakdown", a.requireFeature("query-log"), a.breakdown)
	p.Get("/system/health", a.systemHealth)
	// Local records are core resolver functionality: available in every license state.
	p.Get("/dns/records", a.listRecords)
	p.Post("/dns/records", a.addRecord)
	p.Put("/dns/records/:id", a.updateRecord)
	p.Delete("/dns/records/:id", a.deleteRecord)
	dnsF := p.Group("/dns", a.requireFeature("dns-filtering"))
	dnsF.Get("/blocklist", a.listDomains("dns_blocklist"))
	dnsF.Post("/blocklist", a.addDomain("dns_blocklist"))
	dnsF.Get("/blocklist/export", a.exportList("dns_blocklist"))
	dnsF.Post("/blocklist/import", a.importList("dns_blocklist"))
	dnsF.Delete("/blocklist/:domain", a.deleteDomain("dns_blocklist"))
	dnsF.Get("/allowlist", a.listDomains("dns_allowlist"))
	dnsF.Post("/allowlist", a.addDomain("dns_allowlist"))
	dnsF.Get("/allowlist/export", a.exportList("dns_allowlist"))
	dnsF.Post("/allowlist/import", a.importList("dns_allowlist"))
	dnsF.Delete("/allowlist/:domain", a.deleteDomain("dns_allowlist"))
	dnsF.Get("/sources", a.listSources)
	dnsF.Post("/sources", a.addSource)
	dnsF.Put("/sources/:id", a.updateSource)
	dnsF.Delete("/sources/:id", a.deleteSource)
	dnsF.Post("/sources/:id/refresh", a.refreshSourceNow)
	dnsF.Get("/check", a.checkDomain)
	p.Get("/dns/querylog", a.requireFeature("query-log"), a.queryLog)
	p.Get("/dns/querylog/settings", a.getQueryLogSettings)
	p.Put("/dns/querylog/settings", a.updateQueryLogSettings)
	p.Get("/dns/querylog/export", a.requireFeature("query-log"), a.exportQueryLog)
	p.Get("/dns/top", a.requireFeature("query-log"), a.top)

	fw := p.Group("/firewall", a.requireFeature("firewall"))
	fw.Get("/rules", a.listRules)
	fw.Post("/rules", a.addRule)
	fw.Put("/rules/:id", a.updateRule)
	fw.Delete("/rules/:id", a.deleteRule)
	fw.Post("/apply", a.applyNow)
	fw.Get("/status", a.firewallStatus)
	return app
}

// requireFeature refuses requests when the feature is not licensed.
func (a *App) requireFeature(f string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		st := a.lic.Current()
		if !st.Has(f) {
			return c.Status(fiber.StatusPaymentRequired).JSON(fiber.Map{
				"error": "this feature needs a valid license: " + st.Message, "code": "license_required", "license_mode": st.Mode,
			})
		}
		return c.Next()
	}
}

// AdminCommand runs "isp-netcontrol admin ..." recovery commands against the
// database only (no DNS or console is started).
func AdminCommand(ctx context.Context, cfg Config, args []string) error {
	usage := errors.New("usage: isp-netcontrol admin list | reset-password <email> | reset-2fa <email>")
	if len(args) == 0 {
		return usage
	}
	db, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Ping(ctx); err != nil {
		return fmt.Errorf("database: %w", err)
	}
	switch {
	case args[0] == "list" && len(args) == 1:
		list, err := authkit.ListAdmins(ctx, db)
		if err != nil {
			return err
		}
		for _, x := range list {
			fmt.Printf("%-40s two-factor=%-5v locked=%v\n", x.Email, x.TOTPEnabled, x.Locked)
		}
		return nil
	case args[0] == "reset-password" && len(args) == 2:
		pw, err := authkit.ResetPassword(ctx, db, args[1])
		if err != nil {
			return err
		}
		fmt.Printf("New temporary password for %s: %s\nIt must be changed at the next sign-in.\n", args[1], pw)
		return nil
	case args[0] == "reset-2fa" && len(args) == 2:
		if err := authkit.ResetTOTP(ctx, db, args[1]); err != nil {
			return err
		}
		fmt.Printf("Two-factor authentication removed for %s; it will be set up again at the next sign-in.\n", args[1])
		return nil
	}
	return usage
}
