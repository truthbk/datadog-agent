package events

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type eventHandler struct{}

func (h *eventHandler) HandleEvent(ev *model.Event) {
	ev.ResolveFields()

	log.Debugf("usm handler %w", ev.ProcessContext)
}
