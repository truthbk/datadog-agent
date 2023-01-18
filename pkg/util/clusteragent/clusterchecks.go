// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package clusteragent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/DataDog/datadog-agent/pkg/clusteragent/clusterchecks/types"
)

const (
	dcaClusterChecksPath        = "api/v1/clusterchecks"
	dcaClusterChecksStatusPath  = dcaClusterChecksPath + "/status"
	dcaClusterChecksConfigsPath = dcaClusterChecksPath + "/configs"
)

// PostClusterCheckStatus is called by the clustercheck config provider
func (c *DCAClient) PostClusterCheckStatus(ctx context.Context, identifier string, status types.NodeStatus) (types.StatusResponse, error) {
	var response types.StatusResponse
	queryBody, err := json.Marshal(status)
	if err != nil {
		return response, err
	}

	// https://host:port/api/v1/clusterchecks/status/{identifier}
	err = c.doJSONQueryToLeader(ctx, dcaClusterChecksStatusPath+"/"+identifier, "POST", bytes.NewBuffer(queryBody), &response)
	return response, err
}

// GetClusterCheckConfigs is called by the clustercheck config provider
func (c *DCAClient) GetClusterCheckConfigs(ctx context.Context, identifier string) (types.ConfigResponse, error) {
	var configs types.ConfigResponse

	// https://host:port/api/v1/clusterchecks/configs/{identifier}
	respBody, err := c.doQuery(ctx, dcaClusterChecksConfigsPath+"/"+identifier, "GET", nil, true, true)
	if err != nil {
		return configs, err
	}

	err = json.Unmarshal(respBody, &configs)
	if err != nil {
		return configs, fmt.Errorf("failed to unmarshal JSON from URL: %s, err: %w", dcaClusterChecksConfigsPath+"/"+identifier, err)
	}

	respHasher := sha256.New()
	respHasher.Write(respBody)
	respHash := respHasher.Sum(nil)
	configs.Hash = string(respHash)

	return configs, err
}
