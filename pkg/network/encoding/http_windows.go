// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows && npm
// +build windows,npm

package encoding

import (
	model "github.com/DataDog/agent-payload/v5/process"

	"github.com/DataDog/datadog-agent/pkg/network"
)

func newRequestMatcher() requestMatcher {
	return func(e *httpEncoder, c network.ConnectionStats) (*model.HTTPAggregations, uint64, map[string]struct{}) {
		// in windows data is not normalized so we use the key with the original (src, dst) order
		k := network.HTTPKeyTuplesFromConn(c)[0]
		return e.aggregations[k], e.staticTags[k], e.dynamicTagsSet[k]
	}
}
