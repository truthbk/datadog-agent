// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package processor

import (
	"context"
	"sync"

	"github.com/DataDog/datadog-agent/pkg/util/log"

	"github.com/DataDog/datadog-agent/pkg/logs/config"
	"github.com/DataDog/datadog-agent/pkg/logs/diagnostic"
	"github.com/DataDog/datadog-agent/pkg/logs/internal/metrics"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
)

// A Processor updates messages from an inputChan and pushes
// in an outputChan.
type Processor struct {
	inputChan                 chan *message.Message
	outputChan                chan *message.Message
	processingRules           []*config.ProcessingRule
	encoder                   Encoder
	done                      chan struct{}
	diagnosticMessageReceiver diagnostic.MessageReceiver
	mu                        sync.Mutex
}

// New returns an initialized Processor.
func New(inputChan, outputChan chan *message.Message, processingRules []*config.ProcessingRule, encoder Encoder, diagnosticMessageReceiver diagnostic.MessageReceiver) *Processor {
	return &Processor{
		inputChan:                 inputChan,
		outputChan:                outputChan,
		processingRules:           processingRules,
		encoder:                   encoder,
		done:                      make(chan struct{}),
		diagnosticMessageReceiver: diagnosticMessageReceiver,
	}
}

// Start starts the Processor.
func (p *Processor) Start() {
	go p.run()
}

// Stop stops the Processor,
// this call blocks until inputChan is flushed
func (p *Processor) Stop() {
	close(p.inputChan)
	<-p.done
}

// Flush processes synchronously the messages that this processor has to process.
func (p *Processor) Flush(ctx context.Context) {
	//fmt.Println("[missing log] - flush in processor.go")
	p.mu.Lock()
	//fmt.Println("[missing log] - got the lock")
	defer p.mu.Unlock()
	for {
		select {
		case <-ctx.Done():
			//fmt.Println("[missing log] - context is done")
			return
		default:
			if len(p.inputChan) == 0 {
				//fmt.Println("[missing log] - input chan is empty")
				return
			}
			//fmt.Println("[missing log] - reading messages")
			msg := <-p.inputChan
			if msg.Lambda != nil {
				//fmt.Printf("[missing log] - msg requestID = %s\n", msg.Lambda.RequestID)
			} else {
				//fmt.Println("[missing log] - msg lambda is nil")
			}
			p.processMessage(msg)
		}
	}
}

// run starts the processing of the inputChan
func (p *Processor) run() {
	defer func() {
		p.done <- struct{}{}
	}()
	for msg := range p.inputChan {
		if msg.Lambda != nil {
			//fmt.Printf("[missing log] - in the range loop run() - msg begin requestID = %s content = %s \n", msg.Lambda.RequestID, string(msg.Content))
		}
		p.processMessage(msg)
		if msg.Lambda != nil {
			//fmt.Printf("[missing log] - in the range loop run() - msg end requestID = %s\n content = %s \n", msg.Lambda.RequestID, string(msg.Content))
		}
		p.mu.Lock() // block here if we're trying to flush synchronously
		//nolint:staticcheck
		p.mu.Unlock()
	}
}

func (p *Processor) processMessage(msg *message.Message) {
	if msg.Lambda != nil {
		//fmt.Printf("[missing log] - in the rango loop run() - msg requestID = %s, body = %s\n", msg.Lambda.RequestID, string(msg.Content))
	}
	metrics.LogsDecoded.Add(1)
	metrics.TlmLogsDecoded.Inc()
	if shouldProcess, redactedMsg := p.applyRedactingRules(msg); shouldProcess {
		metrics.LogsProcessed.Add(1)
		metrics.TlmLogsProcessed.Inc()

		p.diagnosticMessageReceiver.HandleMessage(*msg, redactedMsg)

		// Encode the message to its final format
		content, err := p.encoder.Encode(msg, redactedMsg)
		if err != nil {
			log.Error("unable to encode msg ", err)
			return
		}
		msg.Content = content
		if msg.Lambda != nil {
			//fmt.Printf("[missing log] - in processMessage - msg requestID = %s, body = %s\n", msg.Lambda.RequestID, string(msg.Content))
		}
		p.outputChan <- msg
		if msg.Lambda != nil {
			//fmt.Printf("[missing log] - in processMessage outputchan OK - msg requestID = %s, body = %s\n", msg.Lambda.RequestID, string(msg.Content))
		}
	}
}

// applyRedactingRules returns given a message if we should process it or not,
// and a copy of the message with some fields redacted, depending on config
func (p *Processor) applyRedactingRules(msg *message.Message) (bool, []byte) {
	content := msg.Content
	rules := append(p.processingRules, msg.Origin.LogSource.Config.ProcessingRules...)
	for _, rule := range rules {
		switch rule.Type {
		case config.ExcludeAtMatch:
			if rule.Regex.Match(content) {
				return false, nil
			}
		case config.IncludeAtMatch:
			if !rule.Regex.Match(content) {
				return false, nil
			}
		case config.MaskSequences:
			content = rule.Regex.ReplaceAll(content, rule.Placeholder)
		}
	}
	return true, content
}
