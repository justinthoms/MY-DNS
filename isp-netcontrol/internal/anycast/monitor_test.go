package anycast

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type fakeLink struct {
	up    map[string]bool
	calls int
}

func (f *fakeLink) IsUp(n string) (bool, error) { return f.up[n], nil }
func (f *fakeLink) SetUp(n string, up bool) error {
	f.calls++
	f.up[n] = up
	return nil
}

type fakeProbe struct{ fail bool }

func (p *fakeProbe) probe(context.Context) error {
	if p.fail {
		return errors.New("upstream timeout")
	}
	return nil
}

func setup(t *testing.T, mut func(*Config)) (*Monitor, *fakeLink, *fakeProbe, *[]string) {
	t.Helper()
	link := &fakeLink{up: map[string]bool{"anycast0": true}}
	p := &fakeProbe{}
	var notes []string
	m := New(link, p.probe, func(k, msg string) { notes = append(notes, k) })
	c := Defaults()
	c.Enabled, c.MonitorOnly = true, false
	if mut != nil {
		mut(&c)
	}
	if err := m.Configure(c); err != nil {
		t.Fatal(err)
	}
	return m, link, p, &notes
}

func steps(m *Monitor, n int) {
	for i := 0; i < n; i++ {
		m.Step(context.Background())
	}
}

func TestWithdrawAndAnnounceWithHysteresis(t *testing.T) {
	m, link, p, notes := setup(t, nil)
	steps(m, 5)
	if !link.up["anycast0"] || link.calls != 0 {
		t.Fatal("healthy server touched the link")
	}
	p.fail = true
	steps(m, 2)
	if !link.up["anycast0"] {
		t.Fatal("withdrew before the failure threshold")
	}
	steps(m, 1)
	if link.up["anycast0"] {
		t.Fatal("not withdrawn after 3 failures")
	}
	p.fail = false
	steps(m, 2)
	if link.up["anycast0"] {
		t.Fatal("announced before the recovery threshold")
	}
	steps(m, 1)
	if !link.up["anycast0"] || link.calls != 2 {
		t.Fatalf("not announced after recovery (calls %d)", link.calls)
	}
	// A single failure between successes does not flap the route.
	p.fail = true
	steps(m, 1)
	p.fail = false
	steps(m, 1)
	if !link.up["anycast0"] || link.calls != 2 {
		t.Fatal("route flapped on a single failure")
	}
	if got := strings.Join(*notes, ","); !strings.Contains(got, "withdrawn") || !strings.Contains(got, "announced") {
		t.Fatalf("audit notes: %s", got)
	}
}

func TestMonitorOnlyNeverTouchesLink(t *testing.T) {
	m, link, p, _ := setup(t, func(c *Config) { c.MonitorOnly = true })
	p.fail = true
	steps(m, 5)
	st := m.Status()
	if link.calls != 0 || !link.up["anycast0"] || !st.WouldWithdraw || st.Healthy {
		t.Fatalf("monitor-only: calls=%d up=%v would=%v healthy=%v", link.calls, link.up["anycast0"], st.WouldWithdraw, st.Healthy)
	}
}

func TestMaintenanceModeAndDisableRestores(t *testing.T) {
	m, link, _, _ := setup(t, func(c *Config) { c.Mode = "withdraw" })
	steps(m, 1)
	if link.up["anycast0"] {
		t.Fatal("maintenance mode did not withdraw")
	}
	// Turning the feature off gives the interface back.
	c := Defaults()
	if err := m.Configure(c); err != nil {
		t.Fatal(err)
	}
	if !link.up["anycast0"] {
		t.Fatal("interface not restored when disabled")
	}
}

func TestShutdownWithdraws(t *testing.T) {
	m, link, _, _ := setup(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.Run(ctx)
	if link.up["anycast0"] {
		t.Fatal("not withdrawn on shutdown")
	}
}

func TestValidate(t *testing.T) {
	for _, c := range []Config{
		{Enabled: true, Interface: "", IntervalSec: 5, FailThreshold: 3, RiseThreshold: 3},
		{Interface: "x", IntervalSec: 1, FailThreshold: 3, RiseThreshold: 3},
		{Interface: "x", IntervalSec: 5, FailThreshold: 0, RiseThreshold: 3},
		{Interface: "x", IntervalSec: 5, FailThreshold: 3, RiseThreshold: 3, Mode: "maybe"},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

// TestSysLinkInNetns toggles the loopback interface of a private network
// namespace with the real ioctl (root only).
func TestSysLinkInNetns(t *testing.T) {
	if os.Getenv("ANYCAST_NETNS_CHILD") == "1" {
		var l SysLink
		if err := l.SetUp("lo", true); err != nil {
			t.Fatal(err)
		}
		if up, err := l.IsUp("lo"); err != nil || !up {
			t.Fatalf("up: %v %v", up, err)
		}
		if err := l.SetUp("lo", false); err != nil {
			t.Fatal(err)
		}
		if up, _ := l.IsUp("lo"); up {
			t.Fatal("still up")
		}
		if _, err := l.IsUp("no-such-if0"); err == nil {
			t.Fatal("missing interface not reported")
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not installed")
	}
	exe, _ := os.Executable()
	cmd := exec.Command("unshare", "--net", exe, "-test.run", "^TestSysLinkInNetns$")
	cmd.Env = append(os.Environ(), "ANYCAST_NETNS_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}
