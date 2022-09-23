// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !jmx
// +build !jmx

package log

import (
	"errors"
)

// logger implements the component
type logger struct {
}

func newLogger() (Component, error) {
	return &logger{}, nil
}

// Info implements Component#Info.
func (*logger) Info(v ...interface{}) {}

// Error implements Component#Error.
func (*logger) Error(v ...interface{}) error { return errors.New("(no error: jmx support missing)") }
