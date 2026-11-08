//go:build testclock

package clock

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// TestHooks reports whether this binary was built with the test clock.
const TestHooks = true

// now adds the offset (in seconds, may be negative) stored in the file named
// by NC_TEST_CLOCK_FILE. Never shipped: release builds omit the testclock tag.
func now() time.Time {
	t := time.Now()
	path := os.Getenv("NC_TEST_CLOCK_FILE")
	if path == "" {
		return t
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return t
	}
	secs, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return t
	}
	return t.Add(time.Duration(secs) * time.Second)
}
