package dnsserver

import (
	"hash/maphash"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// Protection configures the resolver's defences against abuse. The zero
// value turns every defence off.
type Protection struct {
	// RateLimit is the number of queries per second one client address may
	// send (0 = no limit); Burst is how many it may send at once. Queries
	// over the limit are dropped without an answer.
	RateLimit int
	Burst     int
	// RateLimitExempt lists clients that are never rate limited (for example
	// a NAT gateway with many subscribers behind it).
	RateLimitExempt []netip.Prefix
	// MinimalANY answers ANY queries over UDP with a small HINFO record
	// (RFC 8482) instead of forwarding them: they are mostly used for
	// amplification attacks.
	MinimalANY bool
	// TortureThreshold: when a domain causes more than this many NXDOMAIN
	// answers from the upstream resolvers in one minute (random-subdomain or
	// "water torture" attack), lookups of uncached names under it are limited
	// to TortureLimit per second for TortureHold; the excess gets SERVFAIL
	// without querying the upstream. 0 turns detection off.
	TortureThreshold int
	TortureLimit     int
	TortureHold      time.Duration
}

// DefaultProtection is used until the settings are saved in the console.
func DefaultProtection() Protection {
	return Protection{RateLimit: 500, Burst: 1000, MinimalANY: true,
		TortureThreshold: 1000, TortureLimit: 20, TortureHold: 10 * time.Minute}
}

func (p Protection) exempt(a netip.Addr) bool {
	for _, n := range p.RateLimitExempt {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

const (
	protShards       = 64
	maxClientsPerSh  = 16384 // bounds memory under a spoofed-source flood
	maxZonesPerShard = 4096
)

var protSeed = maphash.MakeSeed()

// ---- Per-client token buckets ----------------------------------------------

type bucket struct {
	tokens   float64
	last     int64 // unix nanoseconds of the last refill
	drops    uint64
	lastDrop int64
}

type limiterShard struct {
	mu sync.Mutex
	m  map[netip.Addr]*bucket
}

type limiter struct{ shards [protShards]limiterShard }

func newLimiter() *limiter {
	l := &limiter{}
	for i := range l.shards {
		l.shards[i].m = make(map[netip.Addr]*bucket)
	}
	return l
}

// allow takes one token for client a. first reports the first drop of a
// client in a ten-second window, so drops can be logged without flooding the
// query log.
func (l *limiter) allow(a netip.Addr, rate, burst int, now int64) (ok, first bool) {
	if burst < rate {
		burst = rate
	}
	b16 := a.As16()
	sh := &l.shards[maphash.Bytes(protSeed, b16[:])%protShards]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	b := sh.m[a]
	if b == nil {
		if len(sh.m) >= maxClientsPerSh {
			clear(sh.m)
		}
		b = &bucket{tokens: float64(burst), last: now}
		sh.m[a] = b
	}
	b.tokens += float64(now-b.last) / 1e9 * float64(rate)
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, false
	}
	first = now-b.lastDrop > int64(10*time.Second)
	b.drops++
	b.lastDrop = now
	return false, first
}

// sweep forgets clients idle for a minute that have not been limited recently.
func (l *limiter) sweep(now int64) {
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		for a, b := range sh.m {
			if now-b.last > int64(time.Minute) && now-b.lastDrop > int64(time.Hour) {
				delete(sh.m, a)
			}
		}
		sh.mu.Unlock()
	}
}

// LimitedClient is a client whose queries were dropped by the rate limit.
type LimitedClient struct {
	Client   string    `json:"client"`
	Dropped  uint64    `json:"dropped"`
	LastDrop time.Time `json:"last_drop"`
}

func (l *limiter) limited(since int64, n int) []LimitedClient {
	out := []LimitedClient{} // never nil: the console expects a list
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		for a, b := range sh.m {
			if b.drops > 0 && b.lastDrop >= since {
				out = append(out, LimitedClient{Client: a.String(), Dropped: b.drops, LastDrop: time.Unix(0, b.lastDrop).UTC()})
			}
		}
		sh.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dropped > out[j].Dropped })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// ---- Random-subdomain (water torture) detection ------------------------------

type zoneState struct {
	minute    int64 // the minute nx counts
	nx        int   // NXDOMAIN answers (and throttled lookups) this minute
	peak      int   // highest per-minute count while suspected
	since     int64 // when the zone became suspected
	until     int64 // suspected until (unix nanoseconds); 0 = not suspected
	tokens    float64
	last      int64
	throttled uint64
}

type zoneShard struct {
	mu sync.Mutex
	m  map[string]*zoneState
}

type tortureGuard struct{ shards [protShards]zoneShard }

func newTortureGuard() *tortureGuard {
	g := &tortureGuard{}
	for i := range g.shards {
		g.shards[i].m = make(map[string]*zoneState)
	}
	return g
}

// zoneOf returns the registrable domain of name ("x1.example.co.uk." ->
// "example.co.uk"), which is what a random-subdomain attack targets.
func zoneOf(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if z, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
		return z
	}
	return name
}

func (g *tortureGuard) shard(zone string) *zoneShard {
	return &g.shards[maphash.String(protSeed, zone)%protShards]
}

// count adds one NXDOMAIN (or throttled lookup) for zone and starts or
// extends suspicion when the threshold is crossed. It reports whether the
// zone has just become suspected.
func (g *tortureGuard) count(zone string, p *Protection, now int64) (started bool) {
	sh := g.shard(zone)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	z := sh.m[zone]
	if z == nil {
		if len(sh.m) >= maxZonesPerShard {
			for k, v := range sh.m { // drop zones that are not suspected
				if v.until < now {
					delete(sh.m, k)
				}
			}
			if len(sh.m) >= maxZonesPerShard {
				return false
			}
		}
		z = &zoneState{}
		sh.m[zone] = z
	}
	minute := now / int64(time.Minute)
	if z.minute != minute {
		z.minute, z.nx = minute, 0
	}
	z.nx++
	if z.nx < p.TortureThreshold {
		return false
	}
	if z.nx > z.peak {
		z.peak = z.nx
	}
	hold := p.TortureHold
	if hold <= 0 {
		hold = 10 * time.Minute
	}
	started = z.until < now
	if started {
		z.since, z.peak, z.throttled = now, z.nx, 0
		z.tokens, z.last = float64(p.TortureLimit), now
	}
	z.until = now + int64(hold)
	return started
}

// allow reports whether an uncached lookup under zone may go to the
// upstream resolvers.
func (g *tortureGuard) allow(zone string, p *Protection, now int64) bool {
	sh := g.shard(zone)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	z := sh.m[zone]
	if z == nil || z.until < now {
		return true
	}
	z.tokens += float64(now-z.last) / 1e9 * float64(p.TortureLimit)
	if lim := float64(max(p.TortureLimit, 1)); z.tokens > lim {
		z.tokens = lim
	}
	z.last = now
	if z.tokens >= 1 {
		z.tokens--
		return true
	}
	z.throttled++
	return false
}

func (g *tortureGuard) sweep(now int64) {
	for i := range g.shards {
		sh := &g.shards[i]
		sh.mu.Lock()
		for k, z := range sh.m {
			if z.until < now && now/int64(time.Minute)-z.minute > 1 {
				delete(sh.m, k)
			}
		}
		sh.mu.Unlock()
	}
}

// ZoneAlert is a domain under a suspected random-subdomain attack.
type ZoneAlert struct {
	Zone      string    `json:"zone"`
	Since     time.Time `json:"since"`
	Until     time.Time `json:"until"`
	PeakNX    int       `json:"peak_nxdomain_per_minute"`
	Throttled uint64    `json:"throttled"`
}

func (g *tortureGuard) alerts(now int64) []ZoneAlert {
	out := []ZoneAlert{}
	for i := range g.shards {
		sh := &g.shards[i]
		sh.mu.Lock()
		for k, z := range sh.m {
			if z.until >= now {
				out = append(out, ZoneAlert{Zone: k, Since: time.Unix(0, z.since).UTC(), Until: time.Unix(0, z.until).UTC(), PeakNX: z.peak, Throttled: z.throttled})
			}
		}
		sh.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Throttled > out[j].Throttled })
	return out
}

// ---- Status -------------------------------------------------------------------

// ProtectionStatus is what the defences are doing now.
type ProtectionStatus struct {
	RateLimited    uint64          `json:"rate_limited"` // dropped queries since start
	Throttled      uint64          `json:"throttled"`    // SERVFAIL for a suspected domain
	MinimalANY     uint64          `json:"minimal_any"`  // ANY queries answered with HINFO
	LimitedClients []LimitedClient `json:"limited_clients"`
	Zones          []ZoneAlert     `json:"zones"`
}

// ProtectionStatus returns the defences' counters, the clients rate limited
// in the last 15 minutes and the domains currently under suspicion.
func (s *Server) ProtectionStatus() ProtectionStatus {
	now := time.Now().UnixNano()
	return ProtectionStatus{
		RateLimited:    s.stats.rateLimited.Load(),
		Throttled:      s.stats.throttled.Load(),
		MinimalANY:     s.stats.minimalANY.Load(),
		LimitedClients: s.limiter.limited(now-int64(15*time.Minute), 20),
		Zones:          s.torture.alerts(now),
	}
}

// minimalANY is the RFC 8482 answer to an ANY query.
func minimalANY(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	m.Answer = []dns.RR{&dns.HINFO{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: 3600}, Cpu: "RFC8482"}}
	return m
}
