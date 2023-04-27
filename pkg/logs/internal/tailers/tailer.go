package tailers

import (
	"github.com/DataDog/datadog-agent/pkg/logs/internal/status"
	"github.com/DataDog/datadog-agent/pkg/util/startstop"
)

// Tailer the base interface for a tailer.
type Tailer interface {
	startstop.Stoppable

	GetId() string
	GetType() string
	GetInfo() *status.InfoRegistry
}
