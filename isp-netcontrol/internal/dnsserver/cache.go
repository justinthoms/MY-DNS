package dnsserver

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// cache is a small TTL-respecting answer cache.
type cache struct {
	mu      sync.Mutex
	max     int
	entries map[string]cacheEntry
}

type cacheEntry struct {
	msg     *dns.Msg
	stored  time.Time
	expires time.Time
}

func newCache(max int) *cache { return &cache{max: max, entries: map[string]cacheEntry{}} }

func cacheKey(req *dns.Msg) string {
	q := req.Question[0]
	do := false
	if o := req.IsEdns0(); o != nil {
		do = o.Do()
	}
	var sb strings.Builder
	sb.WriteString(strings.ToLower(q.Name))
	sb.WriteByte('|')
	sb.WriteString(dns.TypeToString[q.Qtype])
	sb.WriteByte('|')
	sb.WriteString(dns.ClassToString[q.Qclass])
	if do {
		sb.WriteString("|do")
	}
	return sb.String()
}

func (c *cache) clear() {
	c.mu.Lock()
	c.entries = map[string]cacheEntry{}
	c.mu.Unlock()
}

func minTTL(m *dns.Msg) uint32 {
	ttl := uint32(3600)
	found := false
	for _, sec := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range sec {
			found = true
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	}
	if !found {
		return 30 // negative answer without SOA
	}
	return ttl
}

func (c *cache) put(req, resp *dns.Msg) {
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return
	}
	ttl := minTTL(resp)
	if ttl == 0 {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		// Evict expired entries, then arbitrary ones if still full.
		for k, e := range c.entries {
			if now.After(e.expires) {
				delete(c.entries, k)
			}
		}
		for k := range c.entries {
			if len(c.entries) < c.max {
				break
			}
			delete(c.entries, k)
		}
	}
	c.entries[cacheKey(req)] = cacheEntry{msg: resp.Copy(), stored: now, expires: now.Add(time.Duration(ttl) * time.Second)}
}

func (c *cache) get(req *dns.Msg) *dns.Msg {
	c.mu.Lock()
	e, ok := c.entries[cacheKey(req)]
	c.mu.Unlock()
	now := time.Now()
	if !ok || now.After(e.expires) {
		return nil
	}
	m := e.msg.Copy()
	m.Id = req.Id
	elapsed := uint32(now.Sub(e.stored) / time.Second)
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if rr.Header().Ttl > elapsed {
				rr.Header().Ttl -= elapsed
			} else {
				rr.Header().Ttl = 0
			}
		}
	}
	return m
}
