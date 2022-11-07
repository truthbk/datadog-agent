// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver
// +build kubeapiserver

package patch

import (
	"os"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/log"

	"gopkg.in/yaml.v2"
)

type requestProvider interface {
	start(stopCh <-chan struct{})
	subscribe(kind string) chan patchRequest
}

type fileRequestProvider struct {
	file                  string
	pollInterval          time.Duration
	isLeaderFunc          func() bool
	subscribers           map[string]chan patchRequest
	lastSuccessfulRefresh time.Time
}

var _ requestProvider = &fileRequestProvider{}

func newRequestProvider(isLeaderFunc func() bool) requestProvider {
	// Only the file-based implementation is available at the moment.
	return newFileRequestProvider(isLeaderFunc)
}

func newFileRequestProvider(isLeaderFunc func() bool) *fileRequestProvider {
	return &fileRequestProvider{
		file:         "/etc/datadog-agent/auto-instru.yaml",
		pollInterval: 15 * time.Second,
		isLeaderFunc: isLeaderFunc,
		subscribers:  make(map[string]chan patchRequest),
	}
}

func (frp *fileRequestProvider) subscribe(targetObjKind string) chan patchRequest {
	ch := make(chan patchRequest, 10)
	frp.subscribers[targetObjKind] = ch
	return ch
}

func (frp *fileRequestProvider) start(stopCh <-chan struct{}) {
	ticker := time.NewTicker(frp.pollInterval)
	for {
		select {
		case <-ticker.C:
			if err := frp.refresh(); err != nil {
				log.Errorf(err.Error())
			}
		case <-stopCh:
			log.Info("Shutting down request provider")
			return
		}
	}
}

func (frp *fileRequestProvider) refresh() error {
	if !frp.isLeaderFunc() {
		log.Infof("Not leader, skipping")
		return nil
	}
	requests, err := frp.poll()
	if err != nil {
		return err
	}
	log.Infof("Got %d new patch requests", len(requests))
	for _, req := range requests {
		if ch, found := frp.subscribers[req.TargetObjKind]; found {
			log.Infof("Publishing patch requests for target kind %q", req.TargetObjKind)
			ch <- req
		}
	}
	frp.lastSuccessfulRefresh = time.Now()
	return nil
}

func (frp *fileRequestProvider) poll() ([]patchRequest, error) {
	info, err := os.Stat(frp.file)
	if err != nil {
		return nil, err
	}
	modTime := info.ModTime()
	if frp.lastSuccessfulRefresh.After(modTime) {
		log.Infof("File %q hasn't changed since the last Successful refresh at %v", frp.file, frp.lastSuccessfulRefresh)
		return []patchRequest{}, nil
	}
	content, err := os.ReadFile(frp.file)
	if err != nil {
		return nil, err
	}
	var requests []patchRequest
	err = yaml.Unmarshal(content, &requests)
	return requests, err
}
