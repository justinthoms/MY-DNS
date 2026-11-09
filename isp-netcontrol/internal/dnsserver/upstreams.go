package dnsserver

import (
	"sync"
	"time"
)

// UpstreamStat describes one upstream resolver as seen by real traffic.
type UpstreamStat struct {
	Addr      string     `json:"addr"`
	Queries   uint64     `json:"queries"`
	Failures  uint64     `json:"failures"`
	AvgMs     float64    `json:"avg_ms"`  // average response time of successful queries
	Healthy   *bool      `json:"healthy"` // result of the most recent query; null before the first
	LastError string     `json:"last_error,omitempty"`
	LastOK    *time.Time `json:"last_ok,omitempty"`
	LastFail  *time.Time `json:"last_fail,omitempty"`
}

type upstreamState struct {
	queries, failures uint64
	okUs              uint64
	okN               uint64
	lastOK, lastFail  time.Time
	lastErr           string
	lastWasOK         bool
}

type upstreams struct {
	mu sync.Mutex
	m  map[string]*upstreamState
}

func (u *upstreams) record(addr string, rtt time.Duration, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.m == nil {
		u.m = map[string]*upstreamState{}
	}
	st := u.m[addr]
	if st == nil {
		st = &upstreamState{}
		u.m[addr] = st
	}
	st.queries++
	now := time.Now().UTC()
	if err != nil {
		st.failures++
		st.lastFail, st.lastErr, st.lastWasOK = now, err.Error(), false
		return
	}
	st.okUs += uint64(rtt.Microseconds())
	st.okN++
	st.lastOK, st.lastWasOK = now, true
}

// UpstreamStats reports the configured upstreams in policy order.
func (s *Server) UpstreamStats() []UpstreamStat {
	p := s.policy.Load()
	s.ups.mu.Lock()
	defer s.ups.mu.Unlock()
	out := make([]UpstreamStat, 0, len(p.Upstreams))
	for _, addr := range p.Upstreams {
		x := UpstreamStat{Addr: addr}
		if st := s.ups.m[addr]; st != nil {
			x.Queries, x.Failures, x.LastError = st.queries, st.failures, st.lastErr
			if st.okN > 0 {
				x.AvgMs = float64(st.okUs) / float64(st.okN) / 1000
			}
			ok := st.lastWasOK
			x.Healthy = &ok
			if !st.lastOK.IsZero() {
				t := st.lastOK
				x.LastOK = &t
			}
			if !st.lastFail.IsZero() {
				t := st.lastFail
				x.LastFail = &t
			}
		}
		out = append(out, x)
	}
	return out
}
