package dnsserver

import (
	"sync"
	"time"
)

// UpstreamStat describes one upstream resolver as seen by real traffic.
type UpstreamStat struct {
	Addr    string `json:"addr"`
	Queries uint64 `json:"queries"`
	// Failures counts queries the upstream did not answer usefully: timeouts,
	// network errors and REFUSED. A SERVFAIL answer is not a failure of the
	// upstream (it is usually a broken domain) and is counted in ServFail.
	Failures uint64  `json:"failures"`
	ServFail uint64  `json:"servfail"`
	AvgMs    float64 `json:"avg_ms"` // average response time of answered queries
	// Healthy is false after 3 failures in a row; null before the first query.
	Healthy   *bool      `json:"healthy"`
	LastError string     `json:"last_error,omitempty"`
	LastOK    *time.Time `json:"last_ok,omitempty"`
	LastFail  *time.Time `json:"last_fail,omitempty"`
}

type upstreamState struct {
	queries, failures, servfail uint64
	okUs                        uint64
	okN                         uint64
	lastOK, lastFail            time.Time
	lastErr                     string
	consecutiveFail             int
}

// unhealthyAfter is how many failures in a row mark an upstream as down.
const unhealthyAfter = 3

// outcome of one query to an upstream.
type outcome int

const (
	answered outcome = iota // NOERROR or NXDOMAIN
	servfail                // the upstream answered SERVFAIL
	failed                  // timeout, network error or REFUSED
)

type upstreams struct {
	mu sync.Mutex
	m  map[string]*upstreamState
}

func (u *upstreams) record(addr string, rtt time.Duration, o outcome, err error) {
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
	switch o {
	case failed:
		st.failures++
		st.consecutiveFail++
		st.lastFail = now
		if err != nil {
			st.lastErr = err.Error()
		}
	case servfail:
		// The upstream is reachable and answering; the name is the problem.
		st.servfail++
		st.consecutiveFail = 0
		st.lastOK = now
	default:
		st.okUs += uint64(rtt.Microseconds())
		st.okN++
		st.consecutiveFail = 0
		st.lastOK = now
	}
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
			x.Queries, x.Failures, x.ServFail, x.LastError = st.queries, st.failures, st.servfail, st.lastErr
			if st.okN > 0 {
				x.AvgMs = float64(st.okUs) / float64(st.okN) / 1000
			}
			ok := st.consecutiveFail < unhealthyAfter
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
