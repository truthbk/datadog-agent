// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package core

import (
	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/log"
)

// BundleParams defines the parameters for this bundle.
type BundleParams struct {
	config config.Params
	log    log.Params
}

func CreateBundleParams2(config config.Params, log log.Params) BundleParams { // $$$ rename to CreateBundleParams
	return BundleParams{
		config: config,
		log:    log,
	}
}

/// *********************************************
/// ***** Temporary code after this line *******
/// WithXXX will be moved to config / log package
/// *********************************************

// CreateAgentBundleParams creates a new BundleParams for the Core Agent
func CreateAgentBundleParams(confFilePath string, configLoadSecrets bool, options ...func(*BundleParams)) BundleParams {
	params := CreateBundleParams(common.DefaultConfPath, options...)
	params.config.ConfFilePath = confFilePath
	params.config.ConfigLoadSecrets = configLoadSecrets
	return params
}

// CreateBundleParams creates a new BundleParams
func CreateBundleParams(defaultConfPath string, options ...func(*BundleParams)) BundleParams {
	bundleParams := BundleParams{
		config: config.Params{DefaultConfPath: defaultConfPath},
	}
	for _, o := range options {
		o(&bundleParams)
	}
	return bundleParams
}

func WithConfigName(name string) func(*BundleParams) {
	return func(b *BundleParams) {
		//	b.ConfigName = name
	}
}

func WithConfigMissingOK(v bool) func(*BundleParams) {
	return func(b *BundleParams) {
		//		b.ConfigMissingOK = v
	}
}

func WithConfigLoadSysProbe(v bool) func(*BundleParams) {
	return func(b *BundleParams) {
		//	b.ConfigLoadSysProbe = v
	}
}

func WithSecurityAgentConfigFilePaths(securityAgentConfigFilePaths []string) func(*BundleParams) {
	return func(b *BundleParams) {
		//	b.SecurityAgentConfigFilePaths = securityAgentConfigFilePaths
	}
}

func WithConfigLoadSecurityAgent(configLoadSecurityAgent bool) func(*BundleParams) {
	return func(b *BundleParams) {
		//	b.ConfigLoadSecurityAgent = configLoadSecurityAgent
	}
}

func WithConfFilePath(confFilePath string) func(*BundleParams) {
	return func(b *BundleParams) {
		//	b.ConfFilePath = confFilePath
	}
}

func WithConfigLoadSecrets(configLoadSecrets bool) func(*BundleParams) {
	return func(b *BundleParams) {
		//	b.ConfigLoadSecrets = configLoadSecrets
	}
}

func WithLogForOneShot(loggerName, level string, overrideFromEnv bool) func(*BundleParams) {
	return func(b *BundleParams) {
		//	*b = b.LogForOneShot(loggerName, level, overrideFromEnv)
	}
}

func WithLogForDaemon(loggerName, logFileConfig, defaultLogFile string) func(*BundleParams) {
	return func(b *BundleParams) {
		//	*b = b.LogForDaemon(loggerName, logFileConfig, defaultLogFile)
	}
}

func WithLogToFile(logFile string) func(*BundleParams) {
	return func(b *BundleParams) {
		//	*b = b.LogToFile(logFile)
	}
}

func (params BundleParams) LogForOneShot(loggerName, level string, overrideFromEnv bool) BundleParams {
	params.log = log.LogForOneShot(loggerName, level, overrideFromEnv)
	return params
}

func (params BundleParams) LogForDaemon(loggerName, logFileConfig, defaultLogFile string) BundleParams {
	params.log = params.log.LogForDaemon(loggerName, logFileConfig, defaultLogFile)
	return params
}
