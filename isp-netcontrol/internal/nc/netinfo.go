package nc

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// Iface describes a network interface of the server (the API runs in the
// host's network namespace, so these are the host's interfaces).
type Iface struct {
	Name         string   `json:"name"`
	Up           bool     `json:"up"`
	Loopback     bool     `json:"loopback"`
	Addrs        []string `json:"addrs"` // CIDR form
	DefaultRoute bool     `json:"default_route"`
	Internal     bool     `json:"internal"` // docker/veth/bridge: hidden by default
}

func internalIface(name string) bool {
	for _, p := range []string{"docker", "veth", "br-", "virbr", "cni", "flannel", "cali", "tun-docker"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// defaultRouteIfaces reads /proc/net/route and /proc/net/ipv6_route.
func defaultRouteIfaces() map[string]bool {
	out := map[string]bool{}
	if f, err := os.Open("/proc/net/route"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) > 2 && fs[1] == "00000000" && fs[0] != "Iface" {
				out[fs[0]] = true
			}
		}
		f.Close()
	}
	if f, err := os.Open("/proc/net/ipv6_route"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			// destination ::/0 with a non-loopback device
			if len(fs) == 10 && fs[0] == strings.Repeat("0", 32) && fs[1] == "00" && fs[9] != "lo" {
				out[fs[9]] = true
			}
		}
		f.Close()
	}
	return out
}

// listInterfaces returns the server's interfaces with their addresses.
func listInterfaces() ([]Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	def := defaultRouteIfaces()
	out := []Iface{}
	for _, it := range ifs {
		x := Iface{Name: it.Name, Up: it.Flags&net.FlagUp != 0, Loopback: it.Flags&net.FlagLoopback != 0,
			DefaultRoute: def[it.Name], Internal: internalIface(it.Name), Addrs: []string{}}
		addrs, _ := it.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				x.Addrs = append(x.Addrs, ipn.String())
			}
		}
		out = append(out, x)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ifaceIPs returns the addresses DNS can bind on an interface: every
// global IPv4/IPv6 address (link-local addresses need a zone and are skipped).
func ifaceIPs(name string) ([]netip.Addr, error) {
	it, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := it.Addrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, ip)
	}
	return out, nil
}
