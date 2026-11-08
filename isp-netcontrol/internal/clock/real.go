//go:build !testclock

package clock

import "time"

func now() time.Time { return time.Now() }

// TestHooks reports whether this binary was built with the test clock.
const TestHooks = false
