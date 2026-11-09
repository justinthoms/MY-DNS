// Command dnsbench load-tests a DNS server (for example ISP NetControl).
//
//	dnsbench load -server 127.0.0.1:53 -c 200 -d 30s -mode cached
//	dnsbench load -server 127.0.0.1:53 -mode unique -domain example.com
//	dnsbench upstream -listen 127.0.0.1:5399      # fast stand-in upstream for lab tests
//
// Modes: cached (a small set of names, mostly cache hits), unique (a new
// name every query, so every query is forwarded upstream), blocked (random
// subdomains of -domain, which should be on the block list).
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dnsbench load|upstream [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "load":
		load(os.Args[2:])
	case "upstream":
		upstream(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: dnsbench load|upstream [flags]")
		os.Exit(2)
	}
}

func reusePort(network, address string, c syscall.RawConn) error {
	var err error
	_ = c.Control(func(fd uintptr) { err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1) })
	return err
}

// upstream answers every A/AAAA query immediately, from one socket per CPU.
func upstream(args []string) {
	fs := flag.NewFlagSet("upstream", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:5399", "address to answer on")
	_ = fs.Parse(args)
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 1)}}
		case dns.TypeAAAA:
			m.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: net.ParseIP("2001:db8::1")}}
		}
		_ = w.WriteMsg(m)
	})
	lc := net.ListenConfig{Control: reusePort}
	for i := 0; i < runtime.NumCPU(); i++ {
		pc, err := lc.ListenPacket(nil, "udp", *listen) //nolint:staticcheck // nil context is fine for a CLI
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		go func() { _ = (&dns.Server{PacketConn: pc, Handler: h}).ActivateAndServe() }()
	}
	fmt.Printf("stand-in upstream on %s (%d sockets)\n", *listen, runtime.NumCPU())
	select {}
}

func load(args []string) {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:53", "DNS server to test")
	conc := fs.Int("c", 100, "concurrent clients")
	dur := fs.Duration("d", 20*time.Second, "test duration")
	mode := fs.String("mode", "cached", "cached | unique | blocked")
	domain := fs.String("domain", "example.com", "domain for unique/blocked names")
	timeout := fs.Duration("timeout", time.Second, "per-query timeout")
	_ = fs.Parse(args)

	var sent, ok, timeouts, refused atomic.Uint64
	var rcodes sync.Map
	lat := make([][]time.Duration, *conc)
	var seq atomic.Uint64
	cachedNames := make([]string, 200)
	for i := range cachedNames {
		cachedNames[i] = dns.Fqdn("host" + strconv.Itoa(i) + "." + *domain)
	}
	deadline := time.Now().Add(*dur)
	var wg sync.WaitGroup
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			conn, err := net.Dial("udp", *server)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			defer conn.Close()
			rnd := rand.New(rand.NewSource(int64(w)))
			buf := make([]byte, 4096)
			m := new(dns.Msg)
			for time.Now().Before(deadline) {
				var name string
				switch *mode {
				case "unique", "blocked":
					name = dns.Fqdn(strconv.FormatUint(seq.Add(1), 36) + "-" + strconv.Itoa(rnd.Intn(1e6)) + "." + *domain)
				default:
					name = cachedNames[rnd.Intn(len(cachedNames))]
				}
				m.SetQuestion(name, dns.TypeA)
				m.Id = dns.Id()
				out, _ := m.Pack()
				t0 := time.Now()
				sent.Add(1)
				if _, err := conn.Write(out); err != nil {
					continue
				}
				_ = conn.SetReadDeadline(time.Now().Add(*timeout))
				for {
					n, err := conn.Read(buf)
					if err != nil {
						if ne, isNet := err.(net.Error); isNet && ne.Timeout() {
							timeouts.Add(1)
						} else {
							refused.Add(1) // nothing listening (ICMP port unreachable)
							time.Sleep(10 * time.Millisecond)
						}
						break
					}
					var r dns.Msg
					if r.Unpack(buf[:n]) != nil || r.Id != m.Id {
						continue // late answer to an earlier query
					}
					ok.Add(1)
					lat[w] = append(lat[w], time.Since(t0))
					v, _ := rcodes.LoadOrStore(dns.RcodeToString[r.Rcode], new(atomic.Uint64))
					v.(*atomic.Uint64).Add(1)
					break
				}
			}
		}(w)
	}
	wg.Wait()
	var all []time.Duration
	for _, l := range lat {
		all = append(all, l...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	q := func(p float64) time.Duration {
		if len(all) == 0 {
			return 0
		}
		return all[int(float64(len(all)-1)*p)]
	}
	fmt.Printf("mode=%s clients=%d duration=%s\n", *mode, *conc, *dur)
	fmt.Printf("answered %d / sent %d (timeouts %d, connection refused %d) -> %.0f queries/s\n", ok.Load(), sent.Load(), timeouts.Load(), refused.Load(), float64(ok.Load())/dur.Seconds())
	fmt.Printf("latency p50 %s  p95 %s  p99 %s  max %s\n", q(0.50).Round(time.Microsecond), q(0.95).Round(time.Microsecond), q(0.99).Round(time.Microsecond), q(1).Round(time.Microsecond))
	rcodes.Range(func(k, v any) bool { fmt.Printf("  %s: %d\n", k, v.(*atomic.Uint64).Load()); return true })
}
