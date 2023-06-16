// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package module

import (
	"context"
	json "encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
	easyjson "github.com/mailru/easyjson"
	jwriter "github.com/mailru/easyjson/jwriter"
	"go.uber.org/atomic"
	"golang.org/x/time/rate"

	pkgconfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/security/common"
	"github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/security/metrics"
	sprobe "github.com/DataDog/datadog-agent/pkg/security/probe"
	"github.com/DataDog/datadog-agent/pkg/security/proto/api"
	"github.com/DataDog/datadog-agent/pkg/security/reporter"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
	"github.com/DataDog/datadog-agent/pkg/security/seclog"
	"github.com/DataDog/datadog-agent/pkg/security/serializers"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/startstop"
	"github.com/DataDog/datadog-agent/pkg/version"
)

// GetStatus returns the status of the module
func (a *APIServer) GetStatus(ctx context.Context, params *api.GetStatusParams) (*api.Status, error) {
	status, err := a.probe.GetConstantFetcherStatus()
	if err != nil {
		return nil, err
	}

	constants := make([]*api.ConstantValueAndSource, 0, len(status.Values))
	for _, v := range status.Values {
		constants = append(constants, &api.ConstantValueAndSource{
			ID:     v.ID,
			Value:  v.Value,
			Source: v.FetcherName,
		})
	}

	apiStatus := &api.Status{
		Environment: &api.EnvironmentStatus{
			Constants: &api.ConstantFetcherStatus{
				Fetchers: status.Fetchers,
				Values:   constants,
			},
		},
		SelfTests: a.cwsConsumer.selfTester.GetStatus(),
	}

	envErrors := a.probe.VerifyEnvironment()
	if envErrors != nil {
		apiStatus.Environment.Warnings = make([]string, len(envErrors.Errors))
		for i, err := range envErrors.Errors {
			apiStatus.Environment.Warnings[i] = err.Error()
		}
	}

	return apiStatus, nil
}

// GetActivityDumpStream waits for activity dumps and forwards them to the stream
func (a *APIServer) GetActivityDumpStream(params *api.ActivityDumpStreamParams, stream api.SecurityModule_GetActivityDumpStreamServer) error {
	// read one activity dump or timeout after one second
	select {
	case dump := <-a.activityDumps:
		if err := stream.Send(dump); err != nil {
			return err
		}
	case <-time.After(time.Second):
		break
	}
	return nil
}

// SendActivityDump queues an activity dump to the chan of activity dumps
func (a *APIServer) SendActivityDump(dump *api.ActivityDumpStreamMessage) {
	// send the dump to the channel
	select {
	case a.activityDumps <- dump:
		break
	default:
		// The channel is full, consume the oldest dump
		oldestDump := <-a.activityDumps
		// Try to send the event again
		select {
		case a.activityDumps <- dump:
			break
		default:
			// Looks like the channel is full again, expire the current message too
			a.expireDump(dump)
			break
		}
		a.expireDump(oldestDump)
		break
	}
}

// DumpDiscarders handles discarder dump requests
func (a *APIServer) DumpDiscarders(ctx context.Context, params *api.DumpDiscardersParams) (*api.DumpDiscardersMessage, error) {
	filePath, err := a.probe.DumpDiscarders()
	if err != nil {
		return nil, err
	}
	seclog.Infof("Discarder dump file path: %s", filePath)

	return &api.DumpDiscardersMessage{DumpFilename: filePath}, nil
}

// DumpProcessCache handles process cache dump requests
func (a *APIServer) DumpProcessCache(ctx context.Context, params *api.DumpProcessCacheParams) (*api.SecurityDumpProcessCacheMessage, error) {
	resolvers := a.probe.GetResolvers()

	filename, err := resolvers.ProcessResolver.Dump(params.WithArgs)
	if err != nil {
		return nil, err
	}

	return &api.SecurityDumpProcessCacheMessage{
		Filename: filename,
	}, nil
}

// DumpActivity handle an activity dump request
func (a *APIServer) DumpActivity(ctx context.Context, params *api.ActivityDumpParams) (*api.ActivityDumpMessage, error) {
	if monitor := a.probe.GetMonitor(); monitor != nil {
		msg, err := monitor.DumpActivity(params)
		if err != nil {
			seclog.Errorf(err.Error())
		}
		return msg, nil
	}

	return nil, fmt.Errorf("monitor not configured")
}

// ListActivityDumps returns the list of active dumps
func (a *APIServer) ListActivityDumps(ctx context.Context, params *api.ActivityDumpListParams) (*api.ActivityDumpListMessage, error) {
	if monitor := a.probe.GetMonitor(); monitor != nil {
		msg, err := monitor.ListActivityDumps(params)
		if err != nil {
			seclog.Errorf(err.Error())
		}
		return msg, nil
	}

	return nil, fmt.Errorf("monitor not configured")
}

// StopActivityDump stops an active activity dump if it exists
func (a *APIServer) StopActivityDump(ctx context.Context, params *api.ActivityDumpStopParams) (*api.ActivityDumpStopMessage, error) {
	if monitor := a.probe.GetMonitor(); monitor != nil {
		msg, err := monitor.StopActivityDump(params)
		if err != nil {
			seclog.Errorf(err.Error())
		}
		return msg, nil
	}

	return nil, fmt.Errorf("monitor not configured")
}

// TranscodingRequest encodes an activity dump following the requested parameters
func (a *APIServer) TranscodingRequest(ctx context.Context, params *api.TranscodingRequestParams) (*api.TranscodingRequestMessage, error) {
	if monitor := a.probe.GetMonitor(); monitor != nil {
		msg, err := monitor.GenerateTranscoding(params)
		if err != nil {
			seclog.Errorf(err.Error())
		}
		return msg, nil
	}

	return nil, fmt.Errorf("monitor not configured")
}

// ListSecurityProfiles returns the list of security profiles
func (a *APIServer) ListSecurityProfiles(ctx context.Context, params *api.SecurityProfileListParams) (*api.SecurityProfileListMessage, error) {
	if monitor := a.probe.GetMonitor(); monitor != nil {
		msg, err := monitor.ListSecurityProfiles(params)
		if err != nil {
			seclog.Errorf(err.Error())
		}
		return msg, nil
	}

	return nil, fmt.Errorf("monitor not configured")
}

// SaveSecurityProfile saves the requested security profile to disk
func (a *APIServer) SaveSecurityProfile(ctx context.Context, params *api.SecurityProfileSaveParams) (*api.SecurityProfileSaveMessage, error) {
	if monitor := a.probe.GetMonitor(); monitor != nil {
		msg, err := monitor.SaveSecurityProfile(params)
		if err != nil {
			seclog.Errorf(err.Error())
		}
		return msg, nil
	}

	return nil, fmt.Errorf("monitor not configured")
}

// DumpNetworkNamespace handles network namespace cache dump requests
func (a *APIServer) DumpNetworkNamespace(ctx context.Context, params *api.DumpNetworkNamespaceParams) (*api.DumpNetworkNamespaceMessage, error) {
	return a.probe.GetResolvers().NamespaceResolver.DumpNetworkNamespaces(params), nil
}

// GetConfig returns config of the runtime security module required by the security agent
func (a *APIServer) GetConfig(ctx context.Context, params *api.GetConfigParams) (*api.SecurityConfigMessage, error) {
	if a.cfg != nil {
		return &api.SecurityConfigMessage{
			FIMEnabled:          a.cfg.FIMEnabled,
			RuntimeEnabled:      a.cfg.RuntimeEnabled,
			ActivityDumpEnabled: a.probe.IsActivityDumpEnabled(),
		}, nil
	}
	return &api.SecurityConfigMessage{}, nil
}

// RunSelfTest runs self test and then reload the current policies
func (a *APIServer) RunSelfTest(ctx context.Context, params *api.RunSelfTestParams) (*api.SecuritySelfTestResultMessage, error) {
	if a.cwsConsumer == nil {
		return nil, errors.New("failed to found module in APIServer")
	}

	if a.cwsConsumer.selfTester == nil {
		return &api.SecuritySelfTestResultMessage{
			Ok:    false,
			Error: "self-tests are disabled",
		}, nil
	}

	if _, err := a.cwsConsumer.RunSelfTest(false); err != nil {
		return &api.SecuritySelfTestResultMessage{
			Ok:    false,
			Error: err.Error(),
		}, nil
	}

	return &api.SecuritySelfTestResultMessage{
		Ok:    true,
		Error: "",
	}, nil
}

// expireDump updates the count of expired dumps
func (a *APIServer) expireDump(dump *api.ActivityDumpStreamMessage) {
	// update metric
	a.expiredDumps.Inc()
	seclog.Tracef("the activity dump server channel is full, a dump of [%s] was dropped\n", dump.GetDump().GetMetadata().GetName())
}
