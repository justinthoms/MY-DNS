package dnsserver

import (
	"hash/maphash"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// cache is a sharded, TTL-respecting answer cache. Each shard has its own
// lock, so concurrent queries rarely wait for each other, and eviction is
// constant time: when a shard is full a few entries are dropped (expired
// ones first) instead of scanning the whole cache.
type cache struct {
	seed   maphash.Seed
	shards [cacheShards]cacheShard
}

const (
	cacheShards   = 64
	evictPerShard = 8
)

type cacheShard struct {
	mu      sync.Mutex
	max     int
	entries map[string]cacheEntry
}

type cacheEntry struct {
	msg     *dns.Msg
	stored  time.Time
	expires time.Time
}

// DefaultCacheSize is the number of answers cached when not configured.
const DefaultCacheSize = 100_000

func newCache(max int) *cache {
	if max < cacheShards {
		max = cacheShards
	}
	c := &cache{seed: maphash.MakeSeed()}
	for i := range c.shards {
		c.shards[i] = cacheShard{max: max / cacheShards, entries: map[string]cacheEntry{}}
	}
	return c
}

func (c *cache) shard(key string) *cacheShard {
	return &c.shards[maphash.String(c.seed, key)%cacheShards]
}

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
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		s.entries = map[string]cacheEntry{}
		s.mu.Unlock()
	}
}

// size returns the number of cached answers.
func (c *cache) size() int {
	n := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		n += len(s.entries)
		s.mu.Unlock()
	}
	return n
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
	key := cacheKey(req)
	now := time.Now()
	e := cacheEntry{msg: resp.Copy(), stored: now, expires: now.Add(time.Duration(ttl) * time.Second)}
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.entries[key]; !exists && len(s.entries) >= s.max {
		// Drop a few entries: expired ones if any are found, otherwise
		// whatever the map yields first (random order). Constant time.
		dropped := 0
		for k, x := range s.entries {
			if now.After(x.expires) || dropped < 1 {
				delete(s.entries, k)
				dropped++
			}
			if dropped >= evictPerShard {
				break
			}
		}
	}
	s.entries[key] = e
}

func (c *cache) get(req *dns.Msg) *dns.Msg {
	key := cacheKey(req)
	s := c.shard(key)
	s.mu.Lock()
	e, ok := s.entries[key]
	s.mu.Unlock()
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

// sweep removes expired entries, one shard at a time.
func (c *cache) sweep() {
	now := time.Now()
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		for k, e := range s.entries {
			if now.After(e.expires) {
				delete(s.entries, k)
			}
		}
		s.mu.Unlock()
	}
}
