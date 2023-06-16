// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows

package module

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-agent/pkg/security/proto/api"
)

// DumpDiscarders handles discarder dump requests
func (a *APIServer) DumpDiscarders(ctx context.Context, params *api.DumpDiscardersParams) (*api.DumpDiscardersMessage, error) {
	return nil, nil
}

// DumpProcessCache handles process cache dump requests
func (a *APIServer) DumpProcessCache(ctx context.Context, params *api.DumpProcessCacheParams) (*api.SecurityDumpProcessCacheMessage, error) {
	return nil, nil
}

// DumpActivity handle an activity dump request
func (a *APIServer) DumpActivity(ctx context.Context, params *api.ActivityDumpParams) (*api.ActivityDumpMessage, error) {
	return nil, fmt.Errorf("activity dumps not supported")
}

// ListActivityDumps returns the list of active dumps
func (a *APIServer) ListActivityDumps(ctx context.Context, params *api.ActivityDumpListParams) (*api.ActivityDumpListMessage, error) {
	return nil, fmt.Errorf("activity dumps not supported")
}

// StopActivityDump stops an active activity dump if it exists
func (a *APIServer) StopActivityDump(ctx context.Context, params *api.ActivityDumpStopParams) (*api.ActivityDumpStopMessage, error) {
	return nil, fmt.Errorf("activity dumps not supported")
}

// TranscodingRequest encodes an activity dump following the requested parameters
func (a *APIServer) TranscodingRequest(ctx context.Context, params *api.TranscodingRequestParams) (*api.TranscodingRequestMessage, error) {
	return nil, fmt.Errorf("activity dumps not supported")
}

// ListSecurityProfiles returns the list of security profiles
func (a *APIServer) ListSecurityProfiles(ctx context.Context, params *api.SecurityProfileListParams) (*api.SecurityProfileListMessage, error) {
	return nil, fmt.Errorf("activity dumps not supported")
}

// SaveSecurityProfile saves the requested security profile to disk
func (a *APIServer) SaveSecurityProfile(ctx context.Context, params *api.SecurityProfileSaveParams) (*api.SecurityProfileSaveMessage, error) {
	return nil, fmt.Errorf("activity dumps not supported")
}

// GetStatus returns the status of the module
func (a *APIServer) GetStatus(ctx context.Context, params *api.GetStatusParams) (*api.Status, error) {
	return &api.Status{}, nil
}

// DumpNetworkNamespace handles network namespace cache dump requests
func (a *APIServer) DumpNetworkNamespace(ctx context.Context, params *api.DumpNetworkNamespaceParams) (*api.DumpNetworkNamespaceMessage, error) {
	return nil, nil
}

// RunSelfTest runs self test and then reload the current policies
func (a *APIServer) RunSelfTest(ctx context.Context, params *api.RunSelfTestParams) (*api.SecuritySelfTestResultMessage, error) {
	return nil, nil
}
