// Copyright (C) 2026 Podomy.
// SPDX-License-Identifier: AGPL-3.0-or-later

package clock

import (
	"os"
	"strconv"
	"time"
)

// Now returns time, if an env variable of offset has been set,
// then the returned time is offset on return.
// It is needed for the regression and simulation tests in resonance.
// Offset env MUST NEVER BE USED IN PRODUCTION.
func Now() time.Time {
	offsetString := os.Getenv("CONCORD_CLOCK_OFFSET")
	if offsetString != "" {
		offset, err := strconv.Atoi(offsetString)

		if err == nil {
			return time.Now().Add(time.Duration(offset) * time.Second)
		}
	}

	return time.Now()
}
