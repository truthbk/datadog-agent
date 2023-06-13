package logsyncorchestrator

import (
	"context"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/log"
	"go.uber.org/atomic"
)

type LogSyncOrchestrator struct {
	TelemetryApiMessageReceivedCount atomic.Uint32
	NbMessageSent                    atomic.Uint32
}

func (l *LogSyncOrchestrator) Wait(retryIdx int, ctx context.Context, flush func(ctx context.Context)) {
	if retryIdx > 20 {
		log.Error("LogSyncOrchestrator.Wait() failed, retryIdx > 20")
	} else {
		receivedCount := l.TelemetryApiMessageReceivedCount.Load()
		sent := l.NbMessageSent.Load()
		if receivedCount != sent {
			log.Debugf("logSync needs to wait (%v/%v)\n", receivedCount, sent)
			flush(ctx)
			time.Sleep(100 * time.Millisecond)
			l.Wait(retryIdx+1, ctx, flush)
		} else {
			log.Debug("logSync is balanced")
		}
	}
}
