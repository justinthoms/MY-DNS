// Package clock is the single source of wall-clock time for ISP NetControl.
// Production builds use the system clock. Builds with the "testclock" tag
// (tests only) can shift time to exercise trial expiry and clock
// tampering without waiting days.
package clock

import "time"

// Now returns the current time.
func Now() time.Time { return now() }
