package dnsserver

import (
	"sync"

	"github.com/miekg/dns"
)

// flight coalesces identical in-flight upstream queries: while one query
// for a name and type is being forwarded, others for the same key wait for
// its answer instead of sending their own.
type flight struct {
	mu    sync.Mutex
	calls map[string]*call
}

type call struct {
	wg   sync.WaitGroup
	resp *dns.Msg
	err  error
}

// do runs fn once per key at a time; every caller gets its own copy of the
// answer. shared reports whether the answer came from another caller's query.
func (f *flight) do(key string, fn func() (*dns.Msg, error)) (resp *dns.Msg, err error, shared bool) {
	f.mu.Lock()
	if f.calls == nil {
		f.calls = map[string]*call{}
	}
	if c, ok := f.calls[key]; ok {
		f.mu.Unlock()
		c.wg.Wait()
		if c.resp != nil {
			return c.resp.Copy(), c.err, true
		}
		return nil, c.err, true
	}
	c := &call{}
	c.wg.Add(1)
	f.calls[key] = c
	f.mu.Unlock()

	c.resp, c.err = fn()
	f.mu.Lock()
	delete(f.calls, key)
	f.mu.Unlock()
	c.wg.Done()
	if c.resp != nil {
		return c.resp.Copy(), c.err, false
	}
	return nil, c.err, false
}
