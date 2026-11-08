package firewall

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestValidateRule(t *testing.T) {
	r, err := ValidateRule("203.0.113.7", "")
	if err != nil || r.CIDR.String() != "203.0.113.7/32" || r.Direction != "both" {
		t.Fatalf("%v %v", r, err)
	}
	r, err = ValidateRule("198.51.100.77/24", "src")
	if err != nil || r.CIDR.String() != "198.51.100.0/24" {
		t.Fatalf("masking: %v %v", r, err)
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "not-an-ip", "10.0.0.0/33"} {
		if _, err := ValidateRule(bad, "both"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := ValidateRule("10.0.0.1", "sideways"); err == nil {
		t.Error("bad direction accepted")
	}
}

func TestScriptOnlyTouchesOwnTable(t *testing.T) {
	rules := []Rule{}
	for _, c := range []struct{ cidr, dir string }{{"203.0.113.0/24", "src"}, {"2001:db8::/32", "both"}, {"198.51.100.9", "dst"}} {
		r, _ := ValidateRule(c.cidr, c.dir)
		rules = append(rules, r)
	}
	s := Script(rules)
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "table ") || strings.HasPrefix(l, "delete ") {
			if !strings.Contains(l, "inet isp_netcontrol") {
				t.Fatalf("script touches another table: %q", l)
			}
		}
		if strings.HasPrefix(l, "flush ruleset") {
			t.Fatal("script flushes the whole ruleset")
		}
	}
	if !strings.Contains(s, "203.0.113.0/24") || !strings.Contains(s, "2001:db8::/32") {
		t.Fatalf("missing elements:\n%s", s)
	}
}

// TestApplyInNetNamespace applies real rules in a throwaway network
// namespace (root only). It checks that a pre-existing foreign table survives
// both apply and remove.
func TestApplyInNetNamespace(t *testing.T) {
	if os.Getenv("NC_NETNS_CHILD") == "1" {
		netnsChild(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not installed")
	}
	exe, _ := os.Executable()
	cmd := exec.Command("unshare", "--net", exe, "-test.run", "^TestApplyInNetNamespace$", "-test.v")
	cmd.Env = append(os.Environ(), "NC_NETNS_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "Operation not permitted") {
			t.Skipf("cannot create a network namespace here: %s", out)
		}
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}

func netnsChild(t *testing.T) {
	ctx := context.Background()
	m := &Manager{Enabled: true}
	// The "host" firewall: a table we do not own.
	if _, err := m.run(ctx, "table inet hostfw {\n chain input { type filter hook input priority 0; policy accept; tcp dport 22 accept; }\n}\n", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	r1, _ := ValidateRule("203.0.113.0/24", "both")
	r2, _ := ValidateRule("203.0.113.0/25", "src") // overlapping: auto-merge must cope
	if err := m.Apply(ctx, []Rule{r1, r2}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := m.Apply(ctx, []Rule{r1}); err != nil { // re-apply replaces atomically
		t.Fatalf("re-apply: %v", err)
	}
	st, err := m.Status(ctx)
	if err != nil || !strings.Contains(st, "203.0.113.0/24") {
		t.Fatalf("status: %v\n%s", err, st)
	}
	if err := m.Remove(ctx); err != nil {
		t.Fatalf("remove: %v", err)
	}
	all, _ := m.run(ctx, "", "list", "ruleset")
	if strings.Contains(all, Table) {
		t.Fatalf("table still present:\n%s", all)
	}
	if !strings.Contains(all, "table inet hostfw") || !strings.Contains(all, "tcp dport 22 accept") {
		t.Fatalf("host firewall was changed:\n%s", all)
	}
	if err := m.Remove(ctx); err != nil { // idempotent
		t.Fatalf("second remove: %v", err)
	}
}
