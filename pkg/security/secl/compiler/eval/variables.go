// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package eval

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"unsafe"
)

var (
	variableRegex         = regexp.MustCompile(`\${[^}]*}`)
	errAppendNotSupported = errors.New("append is not supported")
)

// VariableValue describes a SECL variable value
type VariableValue interface {
	GetEvaluator() interface{}
}

// MutableVariable is the interface implemented by modifiable variables
type MutableVariable[T any] interface {
	Set(ctx *Context[T], value interface{}) error
	Append(ctx *Context[T], value interface{}) error
}

// Variable describes a SECL variable
type Variable[T any] struct {
	setFnc func(ctx *Context[T], value interface{}) error
}

// Set the variable with the specified value
func (v *Variable[T]) Set(ctx *Context[T], value interface{}) error {
	if v.setFnc == nil {
		return errors.New("variable is not mutable")
	}

	return v.setFnc(ctx, value)
}

// Append a value to the variable
func (v *Variable[T]) Append(ctx *Context[T], value interface{}) error {
	return errAppendNotSupported
}

// IntVariable describes an integer variable
type IntVariable[T any] struct {
	Variable[T]
	intFnc func(ctx *Context[T]) int
}

// GetEvaluator returns the variable SECL evaluator
func (i *IntVariable[T]) GetEvaluator() interface{} {
	return &IntEvaluator{
		EvalFnc: func(ctx *Context[T]) int {
			return i.intFnc(ctx)
		},
	}
}

// NewIntVariable returns a new integer variable
func NewIntVariable[T any](intFnc func(ctx *Context[T]) int, setFnc func(ctx *Context[T], value interface{}) error) *IntVariable[T] {
	return &IntVariable[T]{
		Variable: Variable[T]{
			setFnc: setFnc,
		},
		intFnc: intFnc,
	}
}

// StringVariable describes a string variable
type StringVariable[T any] struct {
	Variable[T]
	strFnc func(ctx *Context[T]) string
}

// GetEvaluator returns the variable SECL evaluator
func (s *StringVariable[T]) GetEvaluator() interface{} {
	return &StringEvaluator{
		ValueType: VariableValueType,
		EvalFnc: func(ctx *Context[T]) string {
			return s.strFnc(ctx)
		},
	}
}

// NewStringVariable returns a new string variable
func NewStringVariable[T any](strFnc func(ctx *Context[T]) string, setFnc func(ctx *Context[T], value interface{}) error) *StringVariable[T] {
	return &StringVariable[T]{
		strFnc: strFnc,
		Variable: Variable[T]{
			setFnc: setFnc,
		},
	}
}

// BoolVariable describes a boolean variable
type BoolVariable[T any] struct {
	Variable[T]
	boolFnc func(ctx *Context[T]) bool
}

// GetEvaluator returns the variable SECL evaluator
func (b *BoolVariable[T]) GetEvaluator() interface{} {
	return &BoolEvaluator{
		EvalFnc: func(ctx *Context[T]) bool {
			return b.boolFnc(ctx)
		},
	}
}

// NewBoolVariable returns a new boolean variable
func NewBoolVariable[T any](boolFnc func(ctx *Context[T]) bool, setFnc func(ctx *Context[T], value interface{}) error) *BoolVariable[T] {
	return &BoolVariable[T]{
		boolFnc: boolFnc,
		Variable: Variable[T]{
			setFnc: setFnc,
		},
	}
}

// StringArrayVariable describes a string array variable
type StringArrayVariable[T any] struct {
	Variable[T]
	strFnc func(ctx *Context[T]) []string
}

// GetEvaluator returns the variable SECL evaluator
func (s *StringArrayVariable[T]) GetEvaluator() interface{} {
	return &StringArrayEvaluator{
		EvalFnc: s.strFnc,
	}
}

// Set the array values
func (s *StringArrayVariable[T]) Set(ctx *Context[T], value interface{}) error {
	if s, ok := value.(string); ok {
		value = []string{s}
	}
	return s.Variable.Set(ctx, value)
}

// Append a value to the array
func (s *StringArrayVariable[T]) Append(ctx *Context[T], value interface{}) error {
	return s.Set(ctx, append(s.strFnc(ctx), value.([]string)...))
}

// NewStringArrayVariable returns a new string array variable
func NewStringArrayVariable[T any](strFnc func(ctx *Context[T]) []string, setFnc func(ctx *Context[T], value interface{}) error) *StringArrayVariable[T] {
	return &StringArrayVariable[T]{
		strFnc: strFnc,
		Variable: Variable[T]{
			setFnc: setFnc,
		},
	}
}

// IntArrayVariable describes an integer array variable
type IntArrayVariable[T any] struct {
	Variable[T]
	intFnc func(ctx *Context[T]) []int
}

// GetEvaluator returns the variable SECL evaluator
func (s *IntArrayVariable[T]) GetEvaluator() interface{} {
	return &IntArrayEvaluator{
		EvalFnc: s.intFnc,
	}
}

// Set the array values
func (s *IntArrayVariable[T]) Set(ctx *Context[T], value interface{}) error {
	if i, ok := value.(int); ok {
		value = []int{i}
	}
	return s.Variable.Set(ctx, value)
}

// Append a value to the array
func (s *IntArrayVariable[T]) Append(ctx *Context[T], value interface{}) error {
	return s.Set(ctx, append(s.intFnc(ctx), value.([]int)...))
}

// NewIntArrayVariable returns a new integer array variable
func NewIntArrayVariable[T any](intFnc func(ctx *Context[T]) []int, setFnc func(ctx *Context[T], value interface{}) error) *IntArrayVariable[T] {
	return &IntArrayVariable[T]{
		intFnc: intFnc,
		Variable: Variable[T]{
			setFnc: setFnc,
		},
	}
}

// MutableIntVariable describes a mutable integer variable
type MutableIntVariable[T any] struct {
	Value int
}

// Set the variable with the specified value
func (m *MutableIntVariable[T]) Set(ctx *Context[T], value interface{}) error {
	m.Value = value.(int)
	return nil
}

// Append a value to the integer
func (m *MutableIntVariable[T]) Append(ctx *Context[T], value interface{}) error {
	switch value := value.(type) {
	case int:
		m.Value += value
	default:
		return errAppendNotSupported
	}
	return nil
}

// GetEvaluator returns the variable SECL evaluator
func (m *MutableIntVariable[T]) GetEvaluator() interface{} {
	return &IntEvaluator{
		EvalFnc: func(ctx *Context[T]) int {
			return m.Value
		},
	}
}

// NewMutableIntVariable returns a new mutable integer variable
func NewMutableIntVariable[T any]() *MutableIntVariable[T] {
	return &MutableIntVariable[T]{}
}

// MutableBoolVariable describes a mutable boolean variable
type MutableBoolVariable[T any] struct {
	Value bool
}

// GetEvaluator returns the variable SECL evaluator
func (m *MutableBoolVariable[T]) GetEvaluator() interface{} {
	return &BoolEvaluator{
		EvalFnc: func(ctx *Context[T]) bool {
			return m.Value
		},
	}
}

// Set the variable with the specified value
func (m *MutableBoolVariable[T]) Set(ctx *Context[T], value interface{}) error {
	m.Value = value.(bool)
	return nil
}

// Append a value to the boolean
func (m *MutableBoolVariable[T]) Append(ctx *Context[T], value interface{}) error {
	return errAppendNotSupported
}

// NewMutableBoolVariable returns a new mutable boolean variable
func NewMutableBoolVariable[T any]() *MutableBoolVariable[T] {
	return &MutableBoolVariable[T]{}
}

// MutableStringVariable describes a mutable string variable
type MutableStringVariable[T any] struct {
	Value string
}

// GetEvaluator returns the variable SECL evaluator
func (m *MutableStringVariable[T]) GetEvaluator() interface{} {
	return &StringEvaluator{
		ValueType: VariableValueType,
		EvalFnc: func(ctx *Context[T]) string {
			return m.Value
		},
	}
}

// Append a value to the string
func (m *MutableStringVariable[T]) Append(ctx *Context[T], value interface{}) error {
	switch value := value.(type) {
	case string:
		m.Value += value
	default:
		return errAppendNotSupported
	}
	return nil
}

// Set the variable with the specified value
func (m *MutableStringVariable[T]) Set(ctx *Context[T], value interface{}) error {
	m.Value = value.(string)
	return nil
}

// NewMutableStringVariable returns a new mutable string variable
func NewMutableStringVariable[T any]() *MutableStringVariable[T] {
	return &MutableStringVariable[T]{}
}

// MutableStringArrayVariable describes a mutable string array variable
type MutableStringArrayVariable[T any] struct {
	StringValues
}

// Set the variable with the specified value
func (m *MutableStringArrayVariable[T]) Set(ctx *Context[T], values interface{}) error {
	if s, ok := values.(string); ok {
		values = []string{s}
	}

	m.StringValues = StringValues{}
	for _, v := range values.([]string) {
		m.AppendScalarValue(v)
	}
	return nil
}

// Append a value to the array
func (m *MutableStringArrayVariable[T]) Append(ctx *Context[T], value interface{}) error {
	switch value := value.(type) {
	case string:
		m.AppendScalarValue(value)
	case []string:
		for _, v := range value {
			m.AppendScalarValue(v)
		}
	default:
		return errAppendNotSupported
	}
	return nil
}

// GetEvaluator returns the variable SECL evaluator
func (m *MutableStringArrayVariable[T]) GetEvaluator() interface{} {
	return &StringArrayEvaluator{
		EvalFnc: func(ctx *Context[T]) []string {
			return m.GetScalarValues()
		},
	}
}

// NewMutableStringArrayVariable returns a new mutable string array variable
func NewMutableStringArrayVariable[T any]() *MutableStringArrayVariable[T] {
	return &MutableStringArrayVariable[T]{}
}

// MutableIntArrayVariable describes a mutable integer array variable
type MutableIntArrayVariable[T any] struct {
	Values []int
}

// Set the variable with the specified value
func (m *MutableIntArrayVariable[T]) Set(ctx *Context[T], values interface{}) error {
	if i, ok := values.(int); ok {
		values = []int{i}
	}
	m.Values = values.([]int)
	return nil
}

// Append a value to the array
func (m *MutableIntArrayVariable[T]) Append(ctx *Context[T], value interface{}) error {
	switch value := value.(type) {
	case int:
		m.Values = append(m.Values, value)
	case []int:
		m.Values = append(m.Values, value...)
	default:
		return errAppendNotSupported
	}
	return nil
}

// GetEvaluator returns the variable SECL evaluator
func (m *MutableIntArrayVariable[T]) GetEvaluator() interface{} {
	return &IntArrayEvaluator{
		EvalFnc: func(ctx *Context[T]) []int {
			return m.Values
		},
	}
}

// NewMutableIntArrayVariable returns a new mutable integer array variable
func NewMutableIntArrayVariable[T any]() *MutableIntArrayVariable[T] {
	return &MutableIntArrayVariable[T]{}
}

// Scoper maps a variable to the entity its scoped to
type Scoper[T any] func(ctx *Context[T]) unsafe.Pointer

// GlobalVariables holds a set of global variables
type GlobalVariables[T any] struct{}

// GetVariable returns new variable of the type of the specified value
func (v *GlobalVariables[T]) GetVariable(name string, value interface{}) (VariableValue, error) {
	switch value := value.(type) {
	case bool:
		return NewMutableBoolVariable[T](), nil
	case int:
		return NewMutableIntVariable[T](), nil
	case string:
		return NewMutableStringVariable[T](), nil
	case []string:
		return NewMutableStringArrayVariable[T](), nil
	case []int:
		return NewMutableIntArrayVariable[T](), nil
	default:
		return nil, fmt.Errorf("unsupported value type: %s", reflect.TypeOf(value))
	}
}

// Variables holds a set of variables
type Variables struct {
	vars map[string]interface{}
}

// GetBool returns the boolean value of the specified variable
func (v *Variables) GetBool(name string) bool {
	if _, found := v.vars[name]; !found {
		return false
	}
	return v.vars[name].(bool)
}

// GetInt returns the integer value of the specified variable
func (v *Variables) GetInt(name string) int {
	if _, found := v.vars[name]; !found {
		return 0
	}
	return v.vars[name].(int)
}

// GetString returns the string value of the specified variable
func (v *Variables) GetString(name string) string {
	if _, found := v.vars[name]; !found {
		return ""
	}
	return v.vars[name].(string)
}

// GetStringArray returns the string array value of the specified variable
func (v *Variables) GetStringArray(name string) []string {
	if _, found := v.vars[name]; !found {
		return nil
	}
	return v.vars[name].([]string)
}

// GetIntArray returns the integer array value of the specified variable
func (v *Variables) GetIntArray(name string) []int {
	if _, found := v.vars[name]; !found {
		return nil
	}
	return v.vars[name].([]int)
}

// Set the value of the specified variable
func (v *Variables) Set(name string, value interface{}) bool {
	existed := false
	if v.vars == nil {
		v.vars = make(map[string]interface{})
	} else {
		_, existed = v.vars[name]
	}

	v.vars[name] = value
	return !existed
}

// ScopedVariables holds a set of scoped variables
type ScopedVariables[T any] struct {
	scoper         Scoper[T]
	onNewVariables func(_ unsafe.Pointer)
	vars           map[unsafe.Pointer]*Variables
}

// GetVariable returns new variable of the type of the specified value
func (v *ScopedVariables[T]) GetVariable(name string, value interface{}) (VariableValue, error) {
	getVariables := func(ctx *Context[T]) *Variables {
		return v.vars[v.scoper(ctx)]
	}

	setVariable := func(ctx *Context[T], value interface{}) error {
		key := v.scoper(ctx)
		vars := v.vars[key]
		if vars == nil {
			vars = &Variables{}
			v.vars[key] = vars
			if v.onNewVariables != nil {
				v.onNewVariables(key)
			}
		}
		vars.Set(name, value)
		return nil
	}

	switch value.(type) {
	case int:
		return NewIntVariable(func(ctx *Context[T]) int {
			if vars := getVariables(ctx); vars != nil {
				return vars.GetInt(name)
			}
			return 0
		}, setVariable), nil
	case bool:
		return NewBoolVariable(func(ctx *Context[T]) bool {
			if vars := getVariables(ctx); vars != nil {
				return vars.GetBool(name)
			}
			return false
		}, setVariable), nil
	case string:
		return NewStringVariable(func(ctx *Context[T]) string {
			if vars := getVariables(ctx); vars != nil {
				return vars.GetString(name)
			}
			return ""
		}, setVariable), nil
	case []string:
		return NewStringArrayVariable(func(ctx *Context[T]) []string {
			if vars := getVariables(ctx); vars != nil {
				return vars.GetStringArray(name)
			}
			return nil
		}, setVariable), nil
	case []int:
		return NewIntArrayVariable(func(ctx *Context[T]) []int {
			if vars := getVariables(ctx); vars != nil {
				return vars.GetIntArray(name)
			}
			return nil

		}, setVariable), nil
	default:
		return nil, fmt.Errorf("unsupported variable type %s for '%s'", reflect.TypeOf(value), name)
	}
}

// ReleaseVariable releases a scoped variable
func (v *ScopedVariables[T]) ReleaseVariable(key unsafe.Pointer) {
	delete(v.vars, key)
}

// NewScopedVariables returns a new set of scope variables
func NewScopedVariables[T any](scoper Scoper[T], onNewVariables func(unsafe.Pointer)) *ScopedVariables[T] {
	return &ScopedVariables[T]{
		scoper:         scoper,
		onNewVariables: onNewVariables,
		vars:           make(map[unsafe.Pointer]*Variables),
	}
}
