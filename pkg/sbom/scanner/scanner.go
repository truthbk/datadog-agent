// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package scanner

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/sbom"
	"github.com/DataDog/datadog-agent/pkg/sbom/collectors"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta/telemetry"
)

const (
	scanTimeout = time.Second * 30
)

var (
	globalScanner *Scanner
)

type scanRequest struct {
	sbom.ScanRequest
	collector collectors.Collector
	opts      sbom.ScanOptions
	ch        chan<- sbom.ScanResult
}

type Scanner struct {
	running   bool
	scanQueue chan scanRequest
}

func (s *Scanner) Scan(request sbom.ScanRequest, opts sbom.ScanOptions, ch chan<- sbom.ScanResult) error {
	collectorName := request.Collector()
	collector := collectors.Collectors[collectorName]
	if collector == nil {
		return fmt.Errorf("invalid collector '%s'", collectorName)
	}

	select {
	case s.scanQueue <- scanRequest{ScanRequest: request, collector: collector, ch: ch, opts: opts}:
		return nil
	default:
		return fmt.Errorf("collector queue for '%s' is full", collectorName)
	}
}

func (s *Scanner) Start(ctx context.Context) {
	if s.running {
		return
	}

	go func() {
		s.running = true
		defer func() { s.running = false }()

		for {
			select {
			// We don't want to keep scanning if image channel is not empty but context is expired
			case <-ctx.Done():
				return

			case request, ok := <-s.scanQueue:
				// Channel has been closed we should exit
				if !ok {
					return
				}

				collector := request.collector
				scanContext, cancel := context.WithTimeout(ctx, scanTimeout)
				createdAt := time.Now()

				report, err := collector.Scan(scanContext, request.ScanRequest, request.opts)
				cancel()
				if err != nil {
					log.Errorf("An error occurred while generating SBOM: %s", err)
					continue
				}

				generationDuration := time.Since(createdAt)
				telemetry.SBOMGenerationDuration.Observe(generationDuration.Seconds())

				select {
				case request.ch <- sbom.ScanResult{
					Report:    report,
					CreatedAt: createdAt,
					Duration:  generationDuration,
				}:
				default:
					log.Errorf("Failed to push scanner result into channel")
				}

				if request.opts.WaitAfter != 0 {
					t := time.NewTimer(request.opts.WaitAfter)
					select {
					case <-ctx.Done():
					case <-t.C:
					}
					t.Stop()
				}
			}
		}
	}()
}

// NewScanner creates a new SBOM scanner. Call Start to start the store and its
// collectors.
func NewScanner(cfg config.Config) *Scanner {
	return &Scanner{
		scanQueue: make(chan scanRequest, 500),
	}
}

// CreateGlobalScanner creates a SBOM scanner, sets it as the default
// global one, and returns it. Start() needs to be called before any data
// collection happens.
func CreateGlobalScanner(cfg config.Config) (*Scanner, error) {
	if globalScanner != nil {
		return nil, errors.New("global SBOM scanner already set, should only happen once")
	}

	for name, collector := range collectors.Collectors {
		if err := collector.Init(cfg); err != nil {
			return nil, fmt.Errorf("failed to initialize SBOM collector '%s': %w", name, err)
		}
	}

	globalScanner = NewScanner(cfg)
	return globalScanner, nil
}

// GetGlobalScanner returns a global instance of the SBOM scanner. It does
// not create one if it's not already set (see CreateGlobalScanner) and returns
// nil in that case.
func GetGlobalScanner() *Scanner {
	return globalScanner
}
