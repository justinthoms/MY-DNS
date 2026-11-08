// Package firewall manages ISP NetControl's nftables rules.
//
// ISP NetControl owns exactly one table, "inet isp_netcontrol", and never
// reads, changes or flushes anything else, so the host's own firewall (ufw,
// firewalld, Docker's rules, hand-written rulesets) is left alone. Every apply
// replaces the table atomically in a single nft transaction; removing it
// deletes only that table.
package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Table is the only nftables table ISP NetControl touches.
const (
	Family = "inet"
	Table  = "isp_netcontrol"
)

// Rule blocks traffic from and/or to a network.
type Rule struct {
	CIDR      netip.Prefix
	Direction string // "src", "dst" or "both"
}

// Manager applies rules with the nft command.
type Manager struct {
	NFT     string // path to nft
	Enabled bool   // false: never touch nftables (NC_FIREWALL_ENABLED=false)
}

// ValidateRule normalises and checks a rule.
func ValidateRule(cidr, direction string) (Rule, error) {
	cidr = strings.TrimSpace(cidr)
	var p netip.Prefix
	var err error
	if strings.Contains(cidr, "/") {
		p, err = netip.ParsePrefix(cidr)
	} else {
		var a netip.Addr
		if a, err = netip.ParseAddr(cidr); err == nil {
			p = netip.PrefixFrom(a, a.BitLen())
		}
	}
	if err != nil {
		return Rule{}, fmt.Errorf("%q is not an IP address or CIDR network", cidr)
	}
	p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
	if p.Bits() == 0 {
		return Rule{}, errors.New("refusing to block an entire address family (/0)")
	}
	switch direction {
	case "src", "dst", "both":
	case "":
		direction = "both"
	default:
		return Rule{}, errors.New(`direction must be "src", "dst" or "both"`)
	}
	return Rule{CIDR: p, Direction: direction}, nil
}

func elements(rules []Rule, v6 bool, dir string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rules {
		if r.CIDR.Addr().Is6() != v6 || (r.Direction != dir && r.Direction != "both") {
			continue
		}
		s := r.CIDR.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func setDef(name, typ string, elems []string) string {
	def := fmt.Sprintf("  set %s {\n    type %s\n    flags interval\n    auto-merge\n", name, typ)
	if len(elems) > 0 {
		def += "    elements = { " + strings.Join(elems, ", ") + " }\n"
	}
	return def + "  }\n"
}

// Script renders the complete nft transaction for rules. The leading
// "table …" + "delete table …" pair makes the replacement atomic and works
// whether or not the table already exists.
func Script(rules []Rule) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table %s %s\ndelete table %s %s\n", Family, Table, Family, Table)
	fmt.Fprintf(&b, "table %s %s {\n", Family, Table)
	b.WriteString(setDef("block_src_v4", "ipv4_addr", elements(rules, false, "src")))
	b.WriteString(setDef("block_dst_v4", "ipv4_addr", elements(rules, false, "dst")))
	b.WriteString(setDef("block_src_v6", "ipv6_addr", elements(rules, true, "src")))
	b.WriteString(setDef("block_dst_v6", "ipv6_addr", elements(rules, true, "dst")))
	for _, chain := range []string{"input", "forward", "output"} {
		fmt.Fprintf(&b, "  chain %s {\n    type filter hook %s priority filter - 5; policy accept;\n", chain, chain)
		if chain != "output" {
			b.WriteString("    ip saddr @block_src_v4 counter drop\n    ip6 saddr @block_src_v6 counter drop\n")
		}
		if chain != "input" {
			b.WriteString("    ip daddr @block_dst_v4 counter drop\n    ip6 daddr @block_dst_v6 counter drop\n")
		}
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func (m *Manager) run(ctx context.Context, stdin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	nft := m.NFT
	if nft == "" {
		nft = "nft"
	}
	cmd := exec.CommandContext(ctx, nft, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return out.String(), fmt.Errorf("nft %s: %s", strings.Join(args, " "), msg)
	}
	return out.String(), nil
}

// ErrDisabled is returned when firewall management is switched off.
var ErrDisabled = errors.New("firewall management is disabled on this server (NC_FIREWALL_ENABLED=false)")

// Apply replaces ISP NetControl's table with rules.
func (m *Manager) Apply(ctx context.Context, rules []Rule) error {
	if !m.Enabled {
		return ErrDisabled
	}
	_, err := m.run(ctx, Script(rules), "-f", "-")
	return err
}

// Remove deletes ISP NetControl's table if it exists. Nothing else changes.
func (m *Manager) Remove(ctx context.Context) error {
	if !m.Enabled {
		return nil
	}
	if _, err := m.run(ctx, "", "list", "table", Family, Table); err != nil {
		return nil // not present
	}
	_, err := m.run(ctx, "", "delete", "table", Family, Table)
	return err
}

// Status returns the current ruleset of ISP NetControl's table ("" if absent).
func (m *Manager) Status(ctx context.Context) (string, error) {
	if !m.Enabled {
		return "", ErrDisabled
	}
	out, err := m.run(ctx, "", "list", "table", Family, Table)
	if err != nil {
		if strings.Contains(err.Error(), "No such file") || strings.Contains(err.Error(), "does not exist") {
			return "", nil
		}
		return "", err
	}
	return out, nil
}
