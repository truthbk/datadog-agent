package tailers

import (
	"github.com/DataDog/datadog-agent/pkg/logs/internal/status"
	"github.com/DataDog/datadog-agent/pkg/util/startstop"
)

type TailerType string

type Tailer interface {
	startstop.Stoppable

	GetId() string
	GetType() string
	GetInfo() []status.InfoProvider
}
