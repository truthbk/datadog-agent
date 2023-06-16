// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !linux

package module

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
)

type RuleFilterEvent struct {
}

type RuleFilterModel struct {
}

func NewRuleFilterModel() *RuleFilterModel {
	return &RuleFilterModel{}
}

func (m *RuleFilterModel) NewEvent() eval.Event {
	return &RuleFilterEvent{}
}

func (m *RuleFilterModel) GetEvaluator(field eval.Field, regID eval.RegisterID) (eval.Evaluator, error) {
	return nil, &eval.ErrFieldNotFound{Field: field}
}

func (e *RuleFilterEvent) GetFieldValue(field eval.Field) (interface{}, error) {
	return nil, &eval.ErrFieldNotFound{Field: field}
}
