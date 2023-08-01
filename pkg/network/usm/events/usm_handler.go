package events

import (
	"github.com/DataDog/datadog-agent/pkg/runtime"
	"sync"

	"go.uber.org/atomic"

	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	smodel "github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	// The size of the callbacks queue for pending tasks.
	pendingCallbacksQueueSize = 1000
)

type eventHandler struct {
	sync.RWMutex

	hasExecCallbacks          atomic.Bool
	processExecCallbacksMutex sync.RWMutex
	processExecCallbacks      map[*ProcessCallback]struct{}

	hasExitCallbacks          atomic.Bool
	processExitCallbacksMutex sync.RWMutex
	processExitCallbacks      map[*ProcessCallback]struct{}

	callbackRunner chan func()

	execCount atomic.Uint32
}

type ProcessCallback func(pid int)

func newEventHandler() *eventHandler {
	cpuNum := runtime.NumVCPU()
	callbackRunner := make(chan func(), pendingCallbacksQueueSize)
	pm.callbackRunnersWG.Add(cpm)
	for i := 0; i < cpuNum; i++ {
		go func() {
			defer pm.callbackRunnersWG.Done()
			for call := range pm.callbackRunner {
				if call != nil {
					call()
				}
			}
		}()
	}
}

func (eh *eventHandler) HandleEvent(ev *model.Event) {
	ev.ResolveFields()

	log.Debugf("usm handler %w", ev.ProcessContext)
	switch ev.GetEventType() {
	case smodel.ExecEventType:
		log.Debug("Handling exec event")
		// handleProcessExec locks a mutex to access the exec callbacks array, if it is empty, then we're
		// wasting "resources" to check it. Since it is a hot-code-path, it has some cpu load.
		// Checking an atomic boolean, is an atomic operation, hence much faster.
		if eh.hasExecCallbacks.Load() {
			eh.handleProcessExec(int(ev.PIDContext.Pid))
		}
	case smodel.ExitEventType:
		log.Debug("Handling exit event")
		// handleProcessExit locks a mutex to access the exit callbacks array, if it is empty, then we're
		// wasting "resources" to check it. Since it is a hot-code-path, it has some cpu load.
		// Checking an atomic boolean, is an atomic operation, hence much faster.
		if eh.hasExitCallbacks.Load() {
			eh.handleProcessExit(int(ev.PIDContext.Pid))
		}
	}
}

// handleProcessExec is a callback function called on a given pid that represents a new process.
// we're iterating the relevant callbacks and trigger them.
func (eh *eventHandler) handleProcessExec(pid int) {
	eh.processExecCallbacksMutex.RLock()
	defer eh.processExecCallbacksMutex.RUnlock()

	for callback := range eh.processExecCallbacks {
		temporaryCallback := callback
		eh.callbackRunner <- func() { (*temporaryCallback)(pid) }
	}
}

// handleProcessExit is a callback function called on a given pid that represents an exit event.
// we're iterating the relevant callbacks and trigger them.
func (eh *eventHandler) handleProcessExit(pid int) {
	eh.processExitCallbacksMutex.RLock()
	defer eh.processExitCallbacksMutex.RUnlock()

	for callback := range eh.processExitCallbacks {
		temporaryCallback := callback
		eh.callbackRunner <- func() { (*temporaryCallback)(pid) }
	}
}
