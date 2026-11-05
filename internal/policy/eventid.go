package policy

import (
	"time"

	"github.com/skylarng89/sherlock-waf/internal/ids"
)

// NewEventID returns a ULID for a request's event.
func NewEventID(now time.Time) (string, error) { return ids.New(now) }
