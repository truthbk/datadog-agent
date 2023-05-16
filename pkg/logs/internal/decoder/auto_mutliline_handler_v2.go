// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package decoder

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/benbjohnson/clock"

	"github.com/DataDog/datadog-agent/pkg/logs/internal/status"
	"github.com/DataDog/datadog-agent/pkg/logs/sources"
	"github.com/DataDog/datadog-agent/pkg/telemetry"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var tokenLength = 30
var tokenMatchThreshold = 0.75
var detectionThreshold = 0.1

type tokenCluster struct {
	score  int
	tokens []Token
	sample string
}

// DetectedPattern is a container to safely access a detected multiline pattern
type DetectedTokenPattern struct {
	sync.Mutex
	pattern []Token
}

// Set sets the pattern
func (d *DetectedTokenPattern) Set(pattern []Token) {
	d.Lock()
	defer d.Unlock()
	d.pattern = pattern
}

// Get gets the pattern
func (d *DetectedTokenPattern) Get() []Token {
	d.Lock()
	defer d.Unlock()
	return d.pattern
}

type AutoMultilineHandlerV2 struct {
	multiLineHandler    *MultiLineHandler
	singleLineHandler   *SingleLineHandler
	model               *MarkovChain
	outputFn            func(*Message)
	isRunning           bool
	linesToAssess       int
	linesTested         int
	lineLimit           int
	matchThreshold      float64
	clusterTable        []*tokenCluster
	processFunc         func(message *Message)
	flushTimeout        time.Duration
	source              *sources.ReplaceableSource
	matchTimeout        time.Duration
	timeoutTimer        *clock.Timer
	clk                 clock.Clock
	detectedPattern     *DetectedTokenPattern
	autoMultiLineStatus *status.MappedInfo
}

func NewAutoMultilineHandlerV2(
	outputFn func(*Message),
	lineLimit, linesToAssess int,
	matchThreshold float64,
	matchTimeout time.Duration,
	flushTimeout time.Duration,
	source *sources.ReplaceableSource,
	additionalPatterns []string,
	detectedPattern *DetectedPattern,
	tailerInfo *status.InfoRegistry,
) *AutoMultilineHandlerV2 {

	table := []*tokenCluster{}
	for _, p := range additionalPatterns {
		maxLength := len(p)
		if maxLength > tokenLength {
			maxLength = tokenLength
		}
		sample := p[:maxLength]

		table = append(table, &tokenCluster{
			score:  0,
			tokens: tokenize([]byte(sample), tokenLength),
			sample: sample,
		})

	}

	h := &AutoMultilineHandlerV2{
		model:               trainModel(),
		outputFn:            outputFn,
		isRunning:           true,
		lineLimit:           lineLimit,
		matchThreshold:      matchThreshold,
		clusterTable:        table,
		detectedPattern:     &DetectedTokenPattern{},
		linesToAssess:       linesToAssess,
		flushTimeout:        flushTimeout,
		source:              source,
		matchTimeout:        matchTimeout,
		timeoutTimer:        nil,
		clk:                 clock.New(),
		autoMultiLineStatus: status.NewMappedInfo("Auto Multi-line"),
	}

	h.singleLineHandler = NewSingleLineHandler(outputFn, lineLimit)
	h.processFunc = h.processAndTry
	tailerInfo.Register(h.autoMultiLineStatus)
	h.autoMultiLineStatus.SetMessage("state", "Waiting for logs")

	return h
}

func (h *AutoMultilineHandlerV2) process(message *Message) {
	h.processFunc(message)
}

func (h *AutoMultilineHandlerV2) flushChan() <-chan time.Time {
	if h.singleLineHandler != nil {
		return h.singleLineHandler.flushChan()
	}
	return h.multiLineHandler.flushChan()
}

func (h *AutoMultilineHandlerV2) flush() {
	if h.singleLineHandler != nil {
		h.singleLineHandler.flush()
	} else {
		h.multiLineHandler.flush()
	}
}

func (h *AutoMultilineHandlerV2) processAndTry(message *Message) {

	content := message.Content

	if len(content) <= 0 {
		return
	}
	// Process message before anything else
	h.singleLineHandler.process(message)

	// 1. Tokenize the log
	maxLength := len(content)
	if maxLength > tokenLength {
		maxLength = tokenLength
	}
	sample := content[:maxLength]
	tokens := tokenize(sample, tokenLength)

	// 2. Check if we already have a cluster matching these tokens
	matched := false
	for i, cluster := range h.clusterTable {
		matched = isMatch(tokens, cluster.tokens, tokenMatchThreshold)
		if matched {
			cluster.score++

			// By keeping the scored clusters sorted, the best match always comes first. Since we expect one timestamp to match overwhelmingly
			// it should match most often causing few re-sorts.
			if i != 0 {
				sort.Slice(h.clusterTable, func(i, j int) bool {
					return h.clusterTable[i].score > h.clusterTable[j].score
				})
			}
			break
		}
	}

	// 3. If no match is found, classify the log as a timestamp or not
	if !matched {
		score := h.model.TestFit(tokens)
		log.Debug("Multiline tested with score ", score, string(sample))
		if score > detectionThreshold {
			h.clusterTable = append(h.clusterTable, &tokenCluster{
				score:  0,
				tokens: tokens,
				sample: string(sample),
			})
		}
	}

	if h.timeoutTimer == nil {
		h.timeoutTimer = h.clk.Timer(h.matchTimeout)
	}

	h.linesTested++

	timeout := false
	select {
	case <-h.timeoutTimer.C:
		log.Debug("Multiline auto detect timed out before reaching line test threshold")
		h.autoMultiLineStatus.SetMessage("message2", fmt.Sprintf("Timeout reached. Processed (%d of %d) logs during detection", h.linesTested, h.linesToAssess))
		timeout = true
		break
	default:
	}

	h.autoMultiLineStatus.SetMessage("state", "State: Using auto multi-line handler")
	h.autoMultiLineStatus.SetMessage("message", fmt.Sprintf("Detecting (%d of %d)", h.linesTested, h.linesToAssess))

	if h.linesTested >= h.linesToAssess || timeout {

		match := false
		topMatch := &tokenCluster{
			sample: "none",
		}
		matchRatio := float64(0)
		if len(h.clusterTable) > 0 {
			topMatch = h.clusterTable[0]
			matchRatio = float64(topMatch.score) / float64(h.linesTested)
			match = matchRatio >= h.matchThreshold
		}

		if match {
			h.autoMultiLineStatus.SetMessage("state", "State: Using multi-line handler")
			h.autoMultiLineStatus.SetMessage("message", fmt.Sprintf("Pattern `%v` matched %d lines with a ratio of %f", topMatch.sample, topMatch.score, matchRatio))
			log.Debug(fmt.Sprintf("Pattern `%v` matched %d lines with a ratio of %f - using multi-line handler", topMatch.sample, topMatch.score, matchRatio))
			telemetry.GetStatsTelemetryProvider().Count(autoMultiLineTelemetryMetricName, 1, []string{"success:true"})

			h.detectedPattern.Set(topMatch.tokens)
			h.switchToMultilineHandler(topMatch.tokens)
		} else {
			h.autoMultiLineStatus.SetMessage("state", "State: Using single-line handler")
			h.autoMultiLineStatus.SetMessage("message", fmt.Sprintf("No pattern met the line match threshold: %f during multiline auto detection. Top match was `%v` with a match ratio of: %f", h.matchThreshold, topMatch.sample, matchRatio))
			log.Debugf(fmt.Sprintf("No pattern met the line match threshold: %f during multiline auto detection. Top match was `%v` with a match ratio of: %f - using single-line handler", h.matchThreshold, topMatch.sample, matchRatio))
			telemetry.GetStatsTelemetryProvider().Count(autoMultiLineTelemetryMetricName, 1, []string{"success:false"})

			// Stay with the single line handler and no longer attempt to detect multiline matches.
			h.processFunc = h.singleLineHandler.process
		}
	}
}

func (h *AutoMultilineHandlerV2) switchToMultilineHandler(tokens []Token) {
	h.isRunning = false
	h.singleLineHandler = nil

	// Build and start a multiline-handler
	h.multiLineHandler = NewTokenMultiLineHandler(h.outputFn, tokens, h.flushTimeout, h.lineLimit, true)
	h.source.RegisterInfo(h.multiLineHandler.countInfo)
	h.source.RegisterInfo(h.multiLineHandler.linesCombinedInfo)
	// stay with the multiline handler
	h.processFunc = h.multiLineHandler.process
}

func trainModel() *MarkovChain {
	model := NewMarkovChain()

	timestamps := []string{
		"2021-03-28T13:45:30.123456Z",
		"28/Mar/2021:13:45:30 -0700",
		"Sun, 28 Mar 2021 13:45:30 -0700",
		"2021-03-28 13:45:30",
		"2021-03-28 13:45:30,123",
		"02 Jan 06 15:04 MST",
		"2023-03-28T14:33:53.743350Z",
		"[28/Mar/2023:15:21:28 +0000]",
		"[2023-03-28T15:21:35.680Z]",
		"2023-03-28T15:19:38.578639+00:00",
		"2023-03-28 15:44:53",
		"2022-08-20'T'13:20:10*633+0000",
		"2022 Mar 03 05:12:41.211 PDT",
		"Jan 21 18:20:11 +0000 2022",
		"19/Apr/2022:06:36:15 -0700",
		"Dec 2, 2022 2:39:58 AM",
		"Jun 09 2022 15:28:14",
		"Apr 20 00:00:35 2010",
		"Sep 28 19:00:00 +0000",
		"Mar 16 08:12:04",
		"2022-10-14T22:11:20+0000",
		"2022-07-01T14:59:55.711'+0000'",
		"2022-07-01T14:59:55.711Z",
		"2022-08-19 12:17:55 -0400",
		"2022-08-19 12:17:55-0400",
		"2022-06-26 02:31:29,573",
		"2022/04/12*19:37:50",
		"2022 Apr 13 22:08:13.211*PDT",
		"2022 Mar 10 01:44:20.392",
		"2022-03-10 14:30:12,655+0000",
		"2022-02-27 15:35:20.311",
		"2022-03-12 13:11:34.222-0700",
		"2022-07-22'T'16:28:55.444",
		"2022-09-08'T'03:13:10",
		"2022-03-12'T'17:56:22'-0700'",
		"2022-11-22'T'10:10:15.455",
		"2022-02-11'T'18:31:44",
		"2022-10-30*02:47:33:899",
		"2022-07-04*13:23:55",
		"22-02-11 16:47:35,985 +0000",
		"22-06-26 02:31:29,573",
		"22-04-19 12:00:17",
		"06/01/22 04:11:05",
		"220423 11:42:35",
		"20220423 11:42:35.173",
		"08/10/22*13:33:56",
		"11/22/2022*05:13:11",
		"05/09/2022*08:22:14*612",
		"04/23/22 04:34:22 +0000",
		"10/03/2022 07:29:46 -0700",
		"11:42:35",
		"11:42:35.173",
		"11:42:35,173",
		"23/Apr 11:42:35,173",
		"23/Apr/2022:11:42:35",
		"23/Apr/2022 11:42:35",
		"23-Apr-2022 11:42:35",
		"23-Apr-2022 11:42:35.883",
		"23 Apr 2022 11:42:35",
		"23 Apr 2022 10:32:35*311",
		"0423_11:42:35",
		"0423_11:42:35.883",
		"8/5/2022 3:31:18 AM:234",
		"9/28/2022 2:23:15 PM",
	}

	for _, str := range timestamps {
		model.Add(tokenize([]byte(str), tokenLength))
	}
	model.Compile()
	return model
}
