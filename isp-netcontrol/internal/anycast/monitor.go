// Package anycast withdraws this server's anycast routes when DNS is not
// healthy, and announces them again when it recovers.
//
// It works with any routing protocol run by FRR (iBGP/eBGP, OSPF, IS-IS):
// the anycast addresses live on a dedicated interface (for example a dummy
// interface "anycast0"), FRR announces that interface's connected /32s, and
// this package sets the interface down to withdraw them and up to announce
// them. FRR reacts to the link state on its own; nothing else is changed.
package anycast

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// Link controls an interface. SysLink is the real implementation.
type Link interface {
	IsUp(name string) (bool, error)
	SetUp(name string, up bool) error
}

// Probe checks that DNS is healthy. It must return within ctx's deadline.
type Probe func(ctx context.Context) error

// Config is set from the console.
type Config struct {
	Enabled       bool   `json:"enabled"`
	Interface     string `json:"interface"`
	MonitorOnly   bool   `json:"monitor_only"`   // check and report, never touch the interface
	IntervalSec   int    `json:"interval_sec"`   // seconds between checks
	FailThreshold int    `json:"fail_threshold"` // failures in a row before withdrawing
	RiseThreshold int    `json:"rise_threshold"` // successes in a row before announcing
	Mode          string `json:"mode"`           // "auto", "withdraw" (maintenance) or "announce" (force)
}

// Defaults returns a safe starting configuration (disabled).
func Defaults() Config {
	return Config{Interface: "anycast0", MonitorOnly: true, IntervalSec: 5, FailThreshold: 3, RiseThreshold: 3, Mode: "auto"}
}

// Validate checks ranges; interface safety is checked by the caller, which
// knows the server's routes.
func (c *Config) Validate() error {
	if c.Mode == "" {
		c.Mode = "auto"
	}
	switch {
	case c.Mode != "auto" && c.Mode != "withdraw" && c.Mode != "announce":
		return errors.New(`mode must be "auto", "withdraw" or "announce"`)
	case c.IntervalSec < 2 || c.IntervalSec > 60:
		return errors.New("check interval must be 2 to 60 seconds")
	case c.FailThreshold < 1 || c.FailThreshold > 20:
		return errors.New("failure threshold must be 1 to 20")
	case c.RiseThreshold < 1 || c.RiseThreshold > 20:
		return errors.New("recovery threshold must be 1 to 20")
	case c.Enabled && c.Interface == "":
		return errors.New("choose the anycast interface")
	}
	return nil
}

// Event is one entry of the recent history.
type Event struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"` // withdrawn, announced, check_failed, recovered, error, config
	Message string    `json:"message"`
}

// Status is shown in the console.
type Status struct {
	Config
	LinkUp          bool      `json:"link_up"`
	Healthy         bool      `json:"healthy"`
	ConsecutiveFail int       `json:"consecutive_fail"`
	ConsecutiveOK   int       `json:"consecutive_ok"`
	LastCheck       time.Time `json:"last_check"`
	LastError       string    `json:"last_error"`
	WouldWithdraw   bool      `json:"would_withdraw"` // monitor-only: what auto mode would do
	Events          []Event   `json:"events"`
}

// Monitor runs the health checks.
type Monitor struct {
	link   Link
	probe  Probe
	notify func(kind, msg string) // for the audit log

	mu       sync.Mutex
	cfg      Config
	st       Status
	weDowned bool          // we set the interface down; restore when disabled
	wake     chan struct{} // reconfiguration
}

// New creates a monitor. notify may be nil.
func New(link Link, probe Probe, notify func(kind, msg string)) *Monitor {
	if notify == nil {
		notify = func(string, string) {}
	}
	m := &Monitor{link: link, probe: probe, notify: notify, cfg: Defaults(), wake: make(chan struct{}, 1)}
	m.st.Config = m.cfg
	return m
}

func (m *Monitor) event(kind, msg string) {
	m.st.Events = append(m.st.Events, Event{At: time.Now().UTC(), Kind: kind, Message: msg})
	if len(m.st.Events) > 50 {
		m.st.Events = m.st.Events[len(m.st.Events)-50:]
	}
	log.Printf("anycast: %s: %s", kind, msg)
	if kind != "check_failed" {
		m.notify(kind, msg)
	}
}

// Configure applies a new configuration. Turning the feature off (or
// switching to monitor-only) brings back an interface this monitor took down.
func (m *Monitor) Configure(c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	old := m.cfg
	m.cfg = c
	m.st.Config = c
	if m.weDowned && (!c.Enabled || c.MonitorOnly || c.Interface != old.Interface) {
		if err := m.link.SetUp(old.Interface, true); err != nil {
			m.event("error", "could not bring "+old.Interface+" back up: "+err.Error())
		} else {
			m.event("announced", fmt.Sprintf("%s brought back up because health control was turned off or moved", old.Interface))
			m.weDowned = false
		}
	}
	m.st.ConsecutiveFail, m.st.ConsecutiveOK = 0, 0
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return nil
}

// Status returns a snapshot.
func (m *Monitor) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.st
	st.Events = append([]Event{}, m.st.Events...) // never nil: the console reads .length
	if up, err := m.link.IsUp(m.cfg.Interface); err == nil {
		st.LinkUp = up
	}
	return st
}

// Step runs one check and acts on it. Exported for tests; Run calls it.
func (m *Monitor) Step(ctx context.Context) {
	m.mu.Lock()
	c := m.cfg
	m.mu.Unlock()
	if !c.Enabled {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, time.Duration(c.IntervalSec)*time.Second)
	err := m.probe(pctx)
	cancel()

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg != c {
		return // reconfigured while checking
	}
	m.st.LastCheck = time.Now().UTC()
	if err != nil {
		m.st.ConsecutiveFail++
		m.st.ConsecutiveOK = 0
		m.st.LastError = err.Error()
		if m.st.ConsecutiveFail == 1 || m.st.ConsecutiveFail == c.FailThreshold {
			m.event("check_failed", fmt.Sprintf("health check failed (%d/%d): %v", m.st.ConsecutiveFail, c.FailThreshold, err))
		}
	} else {
		if !m.st.Healthy && m.st.ConsecutiveFail >= c.FailThreshold {
			m.event("recovered", "health checks pass again")
		}
		m.st.ConsecutiveOK++
		m.st.ConsecutiveFail = 0
		m.st.LastError = ""
	}
	if m.st.ConsecutiveFail >= c.FailThreshold {
		m.st.Healthy = false
	} else if m.st.ConsecutiveOK >= c.RiseThreshold {
		m.st.Healthy = true
	}

	up, lerr := m.link.IsUp(c.Interface)
	if lerr != nil {
		m.event("error", lerr.Error())
		return
	}
	// What should the link be?
	want := up
	switch c.Mode {
	case "withdraw":
		want = false
	case "announce":
		want = true
	default:
		if m.st.ConsecutiveFail >= c.FailThreshold {
			want = false
		} else if m.st.ConsecutiveOK >= c.RiseThreshold {
			want = true
		}
	}
	m.st.WouldWithdraw = c.MonitorOnly && up && !want
	if c.MonitorOnly || want == up {
		return
	}
	if err := m.link.SetUp(c.Interface, want); err != nil {
		m.event("error", err.Error())
		return
	}
	if want {
		m.weDowned = false
		m.event("announced", fmt.Sprintf("%s up: routes announced (%s)", c.Interface, reason(c.Mode, "DNS healthy")))
	} else {
		m.weDowned = true
		m.event("withdrawn", fmt.Sprintf("%s down: routes withdrawn (%s)", c.Interface, reason(c.Mode, "DNS unhealthy: "+m.st.LastError)))
	}
}

func reason(mode, auto string) string {
	switch mode {
	case "withdraw":
		return "maintenance mode"
	case "announce":
		return "forced announce"
	}
	return auto
}

// Run checks on the configured interval until ctx ends. On shutdown it
// withdraws the routes (unless monitor-only or forced announce) so traffic
// moves to the other anycast servers while this one is stopped.
func (m *Monitor) Run(ctx context.Context) {
	for {
		m.Step(ctx)
		m.mu.Lock()
		every := time.Duration(m.cfg.IntervalSec) * time.Second
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			m.shutdown()
			return
		case <-m.wake:
		case <-time.After(every):
		}
	}
}

func (m *Monitor) shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.cfg
	if !c.Enabled || c.MonitorOnly || c.Mode == "announce" {
		return
	}
	if up, err := m.link.IsUp(c.Interface); err == nil && up {
		if err := m.link.SetUp(c.Interface, false); err == nil {
			m.weDowned = true
			m.event("withdrawn", c.Interface+" down: ISP NetControl is stopping")
		}
	}
}
