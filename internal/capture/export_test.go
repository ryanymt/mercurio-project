package capture

import "time"

// SetRetryBackoff shortens the wait between upload attempts for the tests.
func SetRetryBackoff(d time.Duration) { retryBackoff = d }
