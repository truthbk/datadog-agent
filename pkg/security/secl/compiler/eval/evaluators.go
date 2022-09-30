// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package eval

import (
	"net"

	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/ast"
)

// Evaluator is the interface of an evaluator
type Evaluator[T any] interface {
	Eval(ctx *Context[T]) interface{}
	IsDeterministicFor(field Field) bool
	GetField() string
	IsStatic() bool
}

// BoolEvaluator returns a bool as result of the evaluation
type BoolEvaluator[T any] struct {
	EvalFnc     BoolEvalFnc[T]
	Field       Field
	Value       bool
	Weight      int
	OpOverrides *OpOverrides

	// used during compilation of partial
	isDeterministic bool
}

// Eval returns the result of the evaluation
func (b *BoolEvaluator[T]) Eval(ctx *Context[T]) interface{} {
	return b.EvalFnc(ctx)
}

// IsDeterministicFor returns whether the evaluator is partial
func (b *BoolEvaluator[T]) IsDeterministicFor(field Field) bool {
	return b.isDeterministic || (b.Field != "" && b.Field == field)
}

// GetField returns field name used by this evaluator
func (b *BoolEvaluator[T]) GetField() string {
	return b.Field
}

// IsStatic returns whether the evaluator is a scalar
func (b *BoolEvaluator[T]) IsStatic() bool {
	return b.EvalFnc == nil
}

// IntEvaluator returns an int as result of the evaluation
type IntEvaluator[T any] struct {
	EvalFnc     func(ctx *Context[T]) int
	Field       Field
	Value       int
	Weight      int
	OpOverrides *OpOverrides

	// used during compilation of partial
	isDeterministic bool
	isDuration      bool
}

// Eval returns the result of the evaluation
func (i *IntEvaluator[T]) Eval(ctx *Context[T]) interface{} {
	return i.EvalFnc(ctx)
}

// IsDeterministicFor returns whether the evaluator is partial
func (i *IntEvaluator[T]) IsDeterministicFor(field Field) bool {
	return i.isDeterministic || (i.Field != "" && i.Field == field)
}

// GetField returns field name used by this evaluator
func (i *IntEvaluator[T]) GetField() string {
	return i.Field
}

// IsStatic returns whether the evaluator is a scalar
func (i *IntEvaluator[T]) IsStatic() bool {
	return i.EvalFnc == nil
}

// StringEvaluator returns a string as result of the evaluation
type StringEvaluator[T any] struct {
	EvalFnc       func(ctx *Context[T]) string
	Field         Field
	Value         string
	Weight        int
	OpOverrides   *OpOverrides
	ValueType     FieldValueType
	StringCmpOpts StringCmpOpts // only Field evaluator can set this value

	// used during compilation of partial
	isDeterministic bool
}

// Eval returns the result of the evaluation
func (s *StringEvaluator[T]) Eval(ctx *Context[T]) interface{} {
	return s.EvalFnc(ctx)
}

// IsDeterministicFor returns whether the evaluator is partial
func (s *StringEvaluator[T]) IsDeterministicFor(field Field) bool {
	return s.isDeterministic || (s.Field != "" && s.Field == field)
}

// GetField returns field name used by this evaluator
func (s *StringEvaluator[T]) GetField() string {
	return s.Field
}

// IsStatic returns whether the evaluator is a scalar
func (s *StringEvaluator[T]) IsStatic() bool {
	return s.EvalFnc == nil
}

// GetValue returns the evaluator value
func (s *StringEvaluator[T]) GetValue(ctx *Context[T]) string {
	if s.EvalFnc == nil {
		return s.Value
	}
	return s.EvalFnc(ctx)
}

// ToStringMatcher returns a StringMatcher of the evaluator
func (s *StringEvaluator[T]) ToStringMatcher(opts StringCmpOpts) (StringMatcher, error) {
	if s.IsStatic() {
		matcher, err := NewStringMatcher(s.ValueType, s.Value, opts)
		if err != nil {
			return nil, err
		}
		return matcher, nil
	}

	return nil, nil
}

// StringArrayEvaluator returns an array of strings
type StringArrayEvaluator[T any] struct {
	EvalFnc       func(ctx *Context[T]) []string
	Values        []string
	Field         Field
	Weight        int
	OpOverrides   *OpOverrides
	StringCmpOpts StringCmpOpts // only Field evaluator can set this value

	// used during compilation of partial
	isDeterministic bool
}

// Eval returns the result of the evaluation
func (s *StringArrayEvaluator[T]) Eval(ctx *Context[T]) interface{} {
	return s.EvalFnc(ctx)
}

// IsDeterministicFor returns whether the evaluator is partial
func (s *StringArrayEvaluator[T]) IsDeterministicFor(field Field) bool {
	return s.isDeterministic || (s.Field != "" && s.Field == field)
}

// GetField returns field name used by this evaluator
func (s *StringArrayEvaluator[T]) GetField() string {
	return s.Field
}

// IsStatic returns whether the evaluator is a scalar
func (s *StringArrayEvaluator[T]) IsStatic() bool {
	return s.EvalFnc == nil
}

// AppendValue append the given value
func (s *StringArrayEvaluator[T]) AppendValue(value string) {
	s.Values = append(s.Values, value)
}

// StringValuesEvaluator returns an array of strings
type StringValuesEvaluator[T any] struct {
	EvalFnc func(ctx *Context[T]) *StringValues
	Values  StringValues
	Weight  int

	// used during compilation of partial
	isDeterministic bool
}

// Eval returns the result of the evaluation
func (s *StringValuesEvaluator[T]) Eval(ctx *Context[T]) interface{} {
	return s.EvalFnc(ctx)
}

// IsDeterministicFor returns whether the evaluator is partial
func (s *StringValuesEvaluator[T]) IsDeterministicFor(field Field) bool {
	return s.isDeterministic
}

// GetField returns field name used by this evaluator
func (s *StringValuesEvaluator[T]) GetField() string {
	return ""
}

// IsStatic returns whether the evaluator is a scalar
func (s *StringValuesEvaluator[T]) IsStatic() bool {
	return s.EvalFnc == nil
}

// AppendFieldValues append field values
func (s *StringValuesEvaluator[T]) AppendFieldValues(values ...FieldValue) {
	for _, value := range values {
		s.Values.AppendFieldValue(value)
	}
}

// Compile the underlying StringValues
func (s *StringValuesEvaluator[T]) Compile(opts StringCmpOpts) error {
	return s.Values.Compile(opts)
}

// SetFieldValues apply field values
func (s *StringValuesEvaluator[T]) SetFieldValues(values ...FieldValue) error {
	return s.Values.SetFieldValues(values...)
}

// AppendMembers add members to the evaluator
func (s *StringValuesEvaluator[T]) AppendMembers(members ...ast.StringMember) {
	values := make([]FieldValue, 0, len(members))
	var value FieldValue

	for _, member := range members {
		if member.Pattern != nil {
			value = FieldValue{
				Value: *member.Pattern,
				Type:  PatternValueType,
			}
		} else if member.Regexp != nil {
			value = FieldValue{
				Value: *member.Regexp,
				Type:  RegexpValueType,
			}
		} else {
			value = FieldValue{
				Value: *member.String,
				Type:  ScalarValueType,
			}
		}
		values = append(values, value)
	}

	s.AppendFieldValues(values...)
}

// IntArrayEvaluator returns an array of int
type IntArrayEvaluator[T any] struct {
	EvalFnc     func(ctx *Context[T]) []int
	Field       Field
	Values      []int
	Weight      int
	OpOverrides *OpOverrides

	// used during compilation of partial
	isDeterministic bool
}

// Eval returns the result of the evaluation
func (i *IntArrayEvaluator[T]) Eval(ctx *Context[T]) interface{} {
	return i.EvalFnc(ctx)
}

// IsDeterministicFor returns whether the evaluator is partial
func (i *IntArrayEvaluator[T]) IsDeterministicFor(field Field) bool {
	return i.isDeterministic || (i.Field != "" && i.Field == field)
}

// GetField returns field name used by this evaluator
func (i *IntArrayEvaluator[T]) GetField() string {
	return i.Field
}

// IsStatic returns whether the evaluator is a scalar
func (i *IntArrayEvaluator[T]) IsStatic() bool {
	return i.EvalFnc == nil
}

// AppendValues to the array evaluator
func (i *IntArrayEvaluator[T]) AppendValues(values ...int) {
	i.Values = append(i.Values, values...)
}

// BoolArrayEvaluator returns an array of bool
type BoolArrayEvaluator[T any] struct {
	EvalFnc     func(ctx *Context[T]) []bool
	Field       Field
	Values      []bool
	Weight      int
	OpOverrides *OpOverrides

	// used during compilation of partial
	isDeterministic bool
}

// Eval returns the result of the evaluation
func (b *BoolArrayEvaluator[T]) Eval(ctx *Context[T]) interface{} {
	return b.EvalFnc(ctx)
}

// IsDeterministicFor returns whether the evaluator is partial
func (b *BoolArrayEvaluator[T]) IsDeterministicFor(field Field) bool {
	return b.isDeterministic || (b.Field != "" && b.Field == field)
}

// GetField returns field name used by this evaluator
func (b *BoolArrayEvaluator[T]) GetField() string {
	return b.Field
}

// IsStatic returns whether the evaluator is a scalar
func (b *BoolArrayEvaluator[T]) IsStatic() bool {
	return b.EvalFnc == nil
}

// CIDREvaluator returns a net.IP
type CIDREvaluator[T any] struct {
	EvalFnc     func(ctx *Context[T]) net.IPNet
	Field       Field
	Value       net.IPNet
	Weight      int
	OpOverrides *OpOverrides
	ValueType   FieldValueType

	// used during compilation of partial
	isDeterministic bool
}

// Eval returns the result of the evaluation
func (s *CIDREvaluator[T]) Eval(ctx *Context[T]) interface{} {
	return s.EvalFnc(ctx)
}

// IsDeterministicFor returns whether the evaluator is partial
func (s *CIDREvaluator[T]) IsDeterministicFor(field Field) bool {
	return s.isDeterministic || (s.Field != "" && s.Field == field)
}

// GetField returns field name used by this evaluator
func (s *CIDREvaluator[T]) GetField() string {
	return s.Field
}

// IsStatic returns whether the evaluator is a scalar
func (s *CIDREvaluator[T]) IsStatic() bool {
	return s.EvalFnc == nil
}

// CIDRValuesEvaluator returns a net.IP
type CIDRValuesEvaluator[T any] struct {
	EvalFnc   func(ctx *Context[T]) *CIDRValues
	Value     CIDRValues
	Weight    int
	ValueType FieldValueType

	// used during compilation of partial
	isDeterministic bool
}

// Eval returns the result of the evaluation
func (s *CIDRValuesEvaluator[T]) Eval(ctx *Context[T]) interface{} {
	return s.EvalFnc(ctx)
}

// IsDeterministicFor returns whether the evaluator is partial
func (s *CIDRValuesEvaluator[T]) IsDeterministicFor(field Field) bool {
	return s.isDeterministic
}

// GetField returns field name used by this evaluator
func (s *CIDRValuesEvaluator[T]) GetField() string {
	return ""
}

// IsStatic returns whether the evaluator is a scalar
func (s *CIDRValuesEvaluator[T]) IsStatic() bool {
	return s.EvalFnc == nil
}

// CIDRArrayEvaluator returns an array of net.IPNet
type CIDRArrayEvaluator[T any] struct {
	EvalFnc     func(ctx *Context[T]) []net.IPNet
	Field       Field
	Value       []net.IPNet
	Weight      int
	OpOverrides *OpOverrides
	ValueType   FieldValueType

	// used during compilation of partial
	isDeterministic bool
}

// Eval returns the result of the evaluation
func (s *CIDRArrayEvaluator[T]) Eval(ctx *Context[T]) interface{} {
	return s.EvalFnc(ctx)
}

// IsDeterministicFor returns whether the evaluator is partial
func (s *CIDRArrayEvaluator[T]) IsDeterministicFor(field Field) bool {
	return s.isDeterministic || (s.Field != "" && s.Field == field)
}

// GetField returns field name used by this evaluator
func (s *CIDRArrayEvaluator[T]) GetField() string {
	return s.Field
}

// IsStatic returns whether the evaluator is a scalar
func (s *CIDRArrayEvaluator[T]) IsStatic() bool {
	return s.EvalFnc == nil
}
