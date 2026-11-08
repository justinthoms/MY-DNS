package nc

import (
	"strings"
	"testing"
)

func TestParseListFormats(t *testing.T) {
	in := strings.Join([]string{
		"\uFEFF# comment",
		"! adblock comment",
		"[Adblock Plus 2.0]",
		"plain.example.com",
		"*.wild.example",
		"0.0.0.0 hosts-a.example hosts-b.example # trailing comment",
		"127.0.0.1 localhost",
		"||adblock.example^",
		"||important.example^$important",
		"||path.example^/banner", // not expressible in DNS
		"||opt.example^$third-party",
		"domain,category,note",
		"csv.example,malware,\"Reported, twice\"",
		"free text line",
		"PLAIN.example.com", // duplicate, different case
	}, "\n")
	entries, skipped, err := parseList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]listEntry{}
	for _, e := range entries {
		got[e.Domain] = e
	}
	for _, want := range []string{"plain.example.com", "wild.example", "hosts-a.example", "hosts-b.example", "adblock.example", "important.example", "csv.example"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s (got %v)", want, entries)
		}
	}
	if len(entries) != 7 {
		t.Errorf("got %d entries, want 7: %v", len(entries), entries)
	}
	if e := got["csv.example"]; e.Category != "malware" || e.Note != "Reported, twice" {
		t.Errorf("csv columns: %+v", e)
	}
	// localhost, path rule, option rule, free text
	if skipped != 4 {
		t.Errorf("skipped = %d, want 4", skipped)
	}
}
