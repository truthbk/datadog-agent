// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package client

import (
	"context"
	"time"

	"github.com/DataDog/datadog-agent/pkg/aggregator/sender"
	"github.com/DataDog/datadog-agent/pkg/config"
	queue "github.com/DataDog/datadog-agent/pkg/util/aggregatingqueue"
	"github.com/DataDog/datadog-agent/pkg/util/clusteragent"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"
)

const (
	subscriber       = "language_detection_client"
	metricPeriod     = 15 * time.Minute
	maxNbItem        = 10
	maxRetentionTime = 1 * time.Minute
)

type payload struct {
	process *workloadmeta.Process
	pod     *workloadmeta.KubernetesPod
}

type Client struct {
	ctx       context.Context
	cfg       config.Config
	store     workloadmeta.Store
	dcaClient clusteragent.DCAClientInterface
	sender    sender.Sender
	queue     chan *payload
}

func NewClient(
	ctx context.Context,
	cfg config.Config,
	store workloadmeta.Store,
	dcaClient clusteragent.DCAClientInterface,
	sender sender.Sender,
) *Client {
	return &Client{
		ctx:   ctx,
		cfg:   cfg,
		store: store,
		queue: queue.NewQueue(maxNbItem, maxRetentionTime, func(entities []*payload) {

		}),
		sender:    sender,
		dcaClient: dcaClient,
	}
}

func (c *Client) sendUsageMetrics() {
	c.sender.Count("datadog.agent.language_detection.client_running", 1.0, "", nil)
	c.sender.Commit()
}

func (c *Client) processEvent(evBundle workloadmeta.EventBundle) {
	close(evBundle.Ch)
	log.Tracef("Processing %d events", len(evBundle.Events))
	for _, event := range evBundle.Events {
		if event.Entity.GetID().Kind == workloadmeta.KindProcess && event.Type == workloadmeta.EventTypeSet {
			process := event.Entity.(*workloadmeta.Process)
			pod, err := c.store.GetKubernetesPodForContainer(process.ContainerId)
			if err != nil {
				log.Debug("skipping language detection for process %s", process.ID)
				continue
			}
			c.queue <- &payload{
				process: process,
				pod:     pod,
			}
		}
	}
}

func (c *Client) StreamLanguages() {
	log.Infof("Starting language detection client")
	defer log.Infof("Shutting down language detection client")

	processEventCh := c.store.Subscribe(
		subscriber,
		workloadmeta.NormalPriority,
		workloadmeta.NewFilter(
			[]workloadmeta.Kind{
				workloadmeta.KindProcess,
			},
			workloadmeta.SourceAll,
			workloadmeta.EventTypeAll,
		),
	)

	periodicFlushTimer := time.NewTicker(time.Duration(c.cfg.GetDuration("language_detection.client_period")))
	defer periodicFlushTimer.Stop()

	metricTicker := time.NewTicker(metricPeriod)
	defer metricTicker.Stop()

	for {
		select {
		case eventBundle := <-processEventCh:
			c.processEvent(eventBundle)
		case <-metricTicker.C:
			c.sendUsageMetrics()
		case <-c.ctx.Done():
			return
		}
	}
}
