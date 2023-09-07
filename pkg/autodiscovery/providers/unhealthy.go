// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package providers

import (
	"context"
	"runtime/debug"

	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type unhealty struct {
	name string
}

func NewUnhealthy(name string) ConfigProvider {
	return unhealty{
		name: name,
	}
}

func (u unhealty) String() string {
	log.Debugf("%s -- %s", u.name, debug.Stack())
	return u.name
}

func (unhealty) GetConfigErrors() map[string]ErrorMsgSet {
	return make(map[string]ErrorMsgSet)
}

func (u unhealty) Stream(context.Context) <-chan integration.ConfigChanges {
	// TODO: Consider when a type of configprovider is CollectingConfigProvider.
	log.Debugf("%s is unhealthy -- %s", u.name, debug.Stack())
	return make(chan integration.ConfigChanges)
}
