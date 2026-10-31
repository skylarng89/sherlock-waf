package server

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// EnvAPIRateLimit sets the control-plane request budget per user or API token
// per minute (default 300). Raise it for scripted callers.
const EnvAPIRateLimit = "SHERLOCK_API_RATE_LIMIT"

// apiRateLimitFromEnv returns 0 (use the default) when unset. A value that is
// not a positive whole number is an error: silently ignoring it would leave an
// operator believing a limit they set was in force.
func apiRateLimitFromEnv() (int, error) {
	v := strings.TrimSpace(os.Getenv(EnvAPIRateLimit))
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s must be a positive whole number of requests per minute (got %q)", EnvAPIRateLimit, v)
	}
	return n, nil
}
