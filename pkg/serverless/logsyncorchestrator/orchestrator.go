package logsyncorchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/atomic"
)

type LogSyncOrchestrator struct {
	TelemetryApiMessageReceivedCount atomic.Uint32
	NbMessageSent                    atomic.Uint32
	Lock                             sync.Mutex
}

func (l *LogSyncOrchestrator) Reset() {
	fmt.Println("reseting the logSyncOrchestrator")
}

func (l *LogSyncOrchestrator) Debug() {
	fmt.Printf("[LogSyncOrchestrator] %v msg received, %v msg sent\n", l.TelemetryApiMessageReceivedCount.Load(), l.NbMessageSent.Load())
}

func (l *LogSyncOrchestrator) Wait(retryIdx int, ctx context.Context, flush func(ctx context.Context)) {
	if retryIdx > 20 {
		panic("logsyncorchestrator.Wait() failed, retryIdx > 20")
	} else {
		receivedCount := l.TelemetryApiMessageReceivedCount.Load()
		sent := l.NbMessageSent.Load()
		if receivedCount != sent {
			fmt.Printf("logSync needs to wait (%v/%v)\n", receivedCount, sent)
			flush(ctx)
			time.Sleep(100 * time.Millisecond)
			l.Wait(retryIdx+1, ctx, flush)
		} else {
			fmt.Println("logSync doesn't need to wait")
		}
	}
}
