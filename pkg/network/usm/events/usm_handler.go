package events

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
)

type eventHandler struct{}

func (h *eventHandler) HandleEvent(ev *model.Event) {
	ev.ResolveFields()

	for _, h := range e.handlers {
		h(ev.ProcessContext)
	}
}
