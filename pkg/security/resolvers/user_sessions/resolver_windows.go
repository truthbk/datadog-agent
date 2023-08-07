// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package user_sessions

import (
	"github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
)

// ResolverOpts defines hash resolver options
type ResolverOpts struct{}

// Resolver represents a cache for mountpoints and the corresponding file systems
type Resolver struct{}

// NewResolver returns a new instance of the hash resolver
func NewResolver(c *config.RuntimeSecurityConfig) (*Resolver, error) {
	return &Resolver{}, nil
}

// ResolveUserSession returns the user session associated to the provided ID
func (r *Resolver) ResolveUserSession(id uint64) *model.UserSessionContext {
	return nil
}
