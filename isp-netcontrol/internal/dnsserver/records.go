package dnsserver

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// RecordTypes lists the record types that can be defined locally.
var RecordTypes = []string{"A", "AAAA", "CNAME", "TXT", "MX", "PTR"}

// BuildRR validates a local record and returns it as a DNS resource record.
// name may start with "*." (wildcard: matches any name below it that has no
// record of its own). For PTR records name may be an IP address, which is
// turned into its in-addr.arpa / ip6.arpa name.
func BuildRR(name, typ string, ttl uint32, value string, priority uint16) (dns.RR, error) {
	typ = strings.ToUpper(strings.TrimSpace(typ))
	name = strings.ToLower(strings.TrimSpace(name))
	value = strings.TrimSpace(value)
	if typ == "PTR" {
		if a, err := netip.ParseAddr(name); err == nil {
			rev, err := dns.ReverseAddr(a.String())
			if err != nil {
				return nil, err
			}
			name = rev
		}
	}
	if err := checkName(name, true); err != nil {
		return nil, err
	}
	if ttl > 86400 {
		return nil, errors.New("TTL must be between 0 and 86400 seconds")
	}
	hdr := dns.RR_Header{Name: dns.Fqdn(name), Class: dns.ClassINET, Ttl: ttl}
	switch typ {
	case "A":
		a, err := netip.ParseAddr(value)
		if err != nil || !a.Is4() {
			return nil, fmt.Errorf("%q is not an IPv4 address", value)
		}
		hdr.Rrtype = dns.TypeA
		return &dns.A{Hdr: hdr, A: net.IP(a.AsSlice())}, nil
	case "AAAA":
		a, err := netip.ParseAddr(value)
		if err != nil || !a.Is6() || a.Is4In6() {
			return nil, fmt.Errorf("%q is not an IPv6 address", value)
		}
		hdr.Rrtype = dns.TypeAAAA
		return &dns.AAAA{Hdr: hdr, AAAA: net.IP(a.AsSlice())}, nil
	case "CNAME", "PTR", "MX":
		target := strings.ToLower(strings.TrimSuffix(value, "."))
		if err := checkName(target, false); err != nil {
			return nil, fmt.Errorf("target: %w", err)
		}
		switch typ {
		case "CNAME":
			if dns.Fqdn(target) == hdr.Name {
				return nil, errors.New("a CNAME cannot point to itself")
			}
			hdr.Rrtype = dns.TypeCNAME
			return &dns.CNAME{Hdr: hdr, Target: dns.Fqdn(target)}, nil
		case "PTR":
			hdr.Rrtype = dns.TypePTR
			return &dns.PTR{Hdr: hdr, Ptr: dns.Fqdn(target)}, nil
		default:
			hdr.Rrtype = dns.TypeMX
			return &dns.MX{Hdr: hdr, Preference: priority, Mx: dns.Fqdn(target)}, nil
		}
	case "TXT":
		if value == "" || len(value) > 2048 {
			return nil, errors.New("TXT value must be 1 to 2048 characters")
		}
		// DNS character strings hold at most 255 bytes: split longer values.
		var parts []string
		for len(value) > 255 {
			parts = append(parts, value[:255])
			value = value[255:]
		}
		parts = append(parts, value)
		hdr.Rrtype = dns.TypeTXT
		return &dns.TXT{Hdr: hdr, Txt: parts}, nil
	}
	return nil, fmt.Errorf("record type must be one of %s", strings.Join(RecordTypes, ", "))
}

func checkName(name string, allowWildcard bool) error {
	n := strings.TrimSuffix(name, ".")
	if allowWildcard {
		n = strings.TrimPrefix(n, "*.")
	}
	if n == "" || len(n) > 253 {
		return fmt.Errorf("%q is not a valid name", name)
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return fmt.Errorf("%q is not a valid name", name)
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return fmt.Errorf("%q is not a valid name", name)
			}
		}
	}
	return nil
}

// Records holds local records keyed by lower-case FQDN ("host.lan." or "*.lan.").
type Records map[string][]dns.RR

// Add stores rr. It refuses a CNAME next to other data for the same name,
// which DNS does not allow.
func (r Records) Add(rr dns.RR) error {
	name := rr.Header().Name
	for _, x := range r[name] {
		isC, wasC := rr.Header().Rrtype == dns.TypeCNAME, x.Header().Rrtype == dns.TypeCNAME
		if isC || wasC {
			return fmt.Errorf("%s: a CNAME cannot coexist with other records for the same name", strings.TrimSuffix(name, "."))
		}
	}
	r[name] = append(r[name], rr)
	return nil
}

// Lookup returns the records for qname: an exact match, otherwise the
// closest wildcard ("*.parent"), rewritten to the queried name.
func (r Records) Lookup(qname string) []dns.RR {
	if len(r) == 0 {
		return nil
	}
	qname = strings.ToLower(dns.Fqdn(qname))
	if rrs, ok := r[qname]; ok {
		return rrs
	}
	labels := dns.SplitDomainName(qname)
	for i := 1; i < len(labels); i++ {
		wc := "*." + strings.Join(labels[i:], ".") + "."
		if rrs, ok := r[wc]; ok {
			out := make([]dns.RR, len(rrs))
			for j, rr := range rrs {
				c := dns.Copy(rr)
				c.Header().Name = qname
				out[j] = c
			}
			return out
		}
	}
	return nil
}

// answerLocal builds the answer for a name that has local records. CNAMEs
// are followed through local records first, then upstream (up to 8 hops).
func (s *Server) answerLocal(p *Policy, req *dns.Msg, rrs []dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.RecursionAvailable = true
	q := req.Question[0]
	for hop := 0; hop < 8; hop++ {
		var cname *dns.CNAME
		matched := false
		for _, rr := range rrs {
			t := rr.Header().Rrtype
			if t == q.Qtype || q.Qtype == dns.TypeANY {
				m.Answer = append(m.Answer, dns.Copy(rr))
				matched = true
			} else if c, ok := rr.(*dns.CNAME); ok {
				cname = c
			}
		}
		if matched || cname == nil {
			return m // answer, or NODATA (the name exists locally without this type)
		}
		m.Answer = append(m.Answer, dns.Copy(cname))
		target := cname.Target
		if next := p.Records.Lookup(target); next != nil {
			rrs = next
			continue
		}
		if p.Filtering {
			if d, _ := p.Decide(target); d == "blocked" {
				return m
			}
		}
		fq := new(dns.Msg)
		fq.SetQuestion(target, q.Qtype)
		if resp, err := s.forward(p, fq); err == nil {
			m.Answer = append(m.Answer, resp.Answer...)
		}
		return m
	}
	return m
}
