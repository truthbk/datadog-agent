// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package core implements the "core" bundle, providing services common to all
// agent flavors and binaries.
//
// The constituent components serve as utilities and are mostly independent of
// one another.  Other components should depend on any components they need.
//
// This bundle does not depend on any other bundles.
package core

import (
	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/internal"
	"github.com/DataDog/datadog-agent/comp/core/log"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// team: agent-shared-components

// BundleParams defines the parameters for this bundle.
type BundleParams = internal.BundleParams

func CreateAgentBundleParams(confFilePath string, configLoadSecrets bool, options ...func(*BundleParams)) BundleParams {
	return CreateBundleParams(confFilePath, configLoadSecrets, common.DefaultConfPath, options...)
}

func CreateBundleParams(confFilePath string, configLoadSecrets bool, defaultConfPath string, options ...func(*BundleParams)) BundleParams {
	bundleParams := BundleParams{
		ConfFilePath:      confFilePath,
		ConfigLoadSecrets: configLoadSecrets,
		DefaultConfPath:   defaultConfPath,
	}
	for _, o := range options {
		o(&bundleParams)
	}
	return bundleParams
}

func WithConfigName(name string) func(*BundleParams) {
	return func(b *BundleParams) {
		b.ConfigName = name
	}
}

func WithConfigMissingOK(v bool) func(*BundleParams) {
	return func(b *BundleParams) {
		b.ConfigMissingOK = v
	}
}

func WithConfigLoadSysProbe(v bool) func(*BundleParams) {
	return func(b *BundleParams) {
		b.ConfigLoadSysProbe = v
	}
}

// Bundle defines the fx options for this bundle.
var Bundle = fxutil.Bundle(
	config.Module,
	log.Module,
)

// MockBundle defines the mock fx options for this bundle.
var MockBundle = fxutil.Bundle(
	config.MockModule,
	log.Module,
)
