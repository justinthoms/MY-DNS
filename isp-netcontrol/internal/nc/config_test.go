package nc

import "testing"

func TestDefaultUpstreamsFromEnv(t *testing.T) {
	saved := defaultUpstreams
	t.Cleanup(func() { defaultUpstreams = saved })
	t.Setenv("NC_DATABASE_URL", "postgres://x")
	t.Setenv("NC_MASTER_KEY", "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=")

	t.Setenv("NC_DEFAULT_UPSTREAMS", "127.0.0.1:5335, 9.9.9.9")
	if _, err := ConfigFromEnv(); err != nil {
		t.Fatal(err)
	}
	got := defaultDNSSettings().Upstreams
	if len(got) != 2 || got[0] != "127.0.0.1:5335" || got[1] != "9.9.9.9:53" {
		t.Fatalf("upstreams = %v", got)
	}
	// The defaults are copied: changing one result must not change the next.
	got[0] = "1.2.3.4:53"
	if defaultDNSSettings().Upstreams[0] != "127.0.0.1:5335" {
		t.Fatal("defaultDNSSettings shares its slice")
	}

	t.Setenv("NC_DEFAULT_UPSTREAMS", "resolver.example")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("a hostname upstream was accepted")
	}
}
