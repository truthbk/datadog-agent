// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package eval

import (
	"fmt"
	"reflect"

	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/ast"
)

// RuleID - ID of a Rule
type RuleID = string

// Rule - Rule object identified by an `ID` containing a SECL `Expression`
type Rule[T any] struct {
	ID             RuleID
	Expression     string
	Tags           []string
	ReplacementCtx ReplacementContext
	Model          Model

	evaluator *RuleEvaluator[T]
	ast       *ast.Rule
}

// RuleEvaluator - Evaluation part of a Rule
type RuleEvaluator[T any] struct {
	Eval        BoolEvalFnc[T]
	EventTypes  []EventType
	FieldValues map[Field][]FieldValue

	partialEvals map[Field]BoolEvalFnc[T]
}

// PartialEval partially evaluation of the Rule with the given Field.
func (r *RuleEvaluator[T]) PartialEval(ctx *Context[T], field Field) (bool, error) {
	eval, ok := r.partialEvals[field]
	if !ok {
		return false, &ErrFieldNotFound{Field: field}
	}

	return eval(ctx), nil
}

func (r *RuleEvaluator[T]) setPartial(field string, partialEval BoolEvalFnc[T]) {
	if r.partialEvals == nil {
		r.partialEvals = make(map[string]BoolEvalFnc[T])
	}
	r.partialEvals[field] = partialEval
}

// GetFields - Returns all the Field that the RuleEvaluator handles
func (r *RuleEvaluator[T]) GetFields() []Field {
	fields := make([]Field, len(r.FieldValues))
	i := 0
	for key := range r.FieldValues {
		fields[i] = key
		i++
	}
	return fields
}

// Eval - Evaluates
func (r *Rule[T]) Eval(ctx *Context[T]) bool {
	return r.evaluator.Eval(ctx)
}

// GetFieldValues returns the values of the given field
func (r *Rule[T]) GetFieldValues(field Field) []FieldValue {
	return r.evaluator.FieldValues[field]
}

// PartialEval - Partial evaluation with the given Field
func (r *Rule[T]) PartialEval(ctx *Context[T], field Field) (bool, error) {
	return r.evaluator.PartialEval(ctx, field)
}

// GetPartialEval - Returns the Partial RuleEvaluator for the given Field
func (r *Rule[T]) GetPartialEval(field Field) BoolEvalFnc[T] {
	return r.evaluator.partialEvals[field]
}

// GetFields - Returns all the Field of the Rule including field of the Macro used
func (r *Rule[T]) GetFields() []Field {
	fields := r.evaluator.GetFields()

	for _, macro := range r.ReplacementCtx.Macros {
		fields = append(fields, macro.GetFields()...)
	}

	return fields
}

// GetEvaluator - Returns the RuleEvaluator of the Rule corresponding to the SECL `Expression`
func (r *Rule[T]) GetEvaluator() *RuleEvaluator[T] {
	return r.evaluator
}

// GetEventTypes - Returns a list of all the event that the `Expression` handles
func (r *Rule[T]) GetEventTypes() ([]EventType, error) {
	if r.evaluator == nil {
		return nil, &ErrRuleNotCompiled{RuleID: r.ID}
	}

	eventTypes := r.evaluator.EventTypes

	for _, macro := range r.ReplacementCtx.Macros {
		eventTypes = append(eventTypes, macro.GetEventTypes()...)
	}

	return eventTypes, nil
}

// GetAst - Returns the representation of the SECL `Expression`
func (r *Rule[T]) GetAst() *ast.Rule {
	return r.ast
}

// Parse - Transforms the SECL `Expression` into its AST representation
func (r *Rule[T]) Parse() error {
	astRule, err := ast.ParseRule(r.Expression)
	if err != nil {
		return err
	}
	r.ast = astRule
	return nil
}

func ruleToEvaluator[T any](rule *ast.Rule, model Model, replCtx ReplacementContext) (*RuleEvaluator[T], error) {
	macros := make(map[MacroID]*MacroEvaluator)
	for id, macro := range replCtx.Macros {
		macros[id] = macro.evaluator
	}
	state := NewState(model, "", macros, replCtx)

	eval, _, err := nodeToEvaluator(rule.BooleanExpression, state)
	if err != nil {
		return nil, err
	}

	evalBool, ok := eval.(*BoolEvaluator[T])
	if !ok {
		return nil, NewTypeError(rule.Pos, reflect.Bool)
	}

	events, err := eventTypesFromFields(model, state)
	if err != nil {
		return nil, err
	}

	// direct value, no bool evaluator, wrap value
	if evalBool.EvalFnc == nil {
		evalBool.EvalFnc = func(ctx *Context[T]) bool {
			return evalBool.Value
		}
	}

	return &RuleEvaluator[T]{
		Eval:        evalBool.EvalFnc,
		EventTypes:  events,
		FieldValues: state.fieldValues,
	}, nil
}

// GenEvaluator - Compile and generates the RuleEvaluator
func (r *Rule[T]) GenEvaluator(model Model, replCtx ReplacementContext) error {
	r.Model = model
	r.ReplacementCtx = replCtx

	if r.ast == nil {
		if err := r.Parse(); err != nil {
			return err
		}
	}

	evaluator, err := ruleToEvaluator[T](r.ast, model, replCtx)
	if err != nil {
		if err, ok := err.(*ErrAstToEval); ok {
			return fmt.Errorf("rule syntax error: %s: %w", err, &ErrRuleParse{pos: err.Pos, expr: r.Expression})
		}
		return fmt.Errorf("rule compilation error: %w", err)
	}
	r.evaluator = evaluator

	return nil
}

func (r *Rule[T]) genMacroPartials() (map[Field]map[MacroID]*MacroEvaluator, error) {
	partials := make(map[Field]map[MacroID]*MacroEvaluator)
	for _, field := range r.GetFields() {
		for id, macro := range r.ReplacementCtx.Macros {
			var err error
			var evaluator *MacroEvaluator
			if macro.ast != nil {
				// NOTE(safchain) this is not working with nested macro. It will be removed once partial
				// will be generated another way
				evaluator, err = macroToEvaluator(macro.ast, r.Model, r.ReplacementCtx, field)
				if err != nil {
					if err, ok := err.(*ErrAstToEval); ok {
						return nil, fmt.Errorf("macro syntax error: %w", &ErrRuleParse{pos: err.Pos})
					}
					return nil, fmt.Errorf("macro compilation error: %w", err)
				}
			} else {
				evaluator = macro.GetEvaluator()
			}

			macroEvaluators, exists := partials[field]
			if !exists {
				macroEvaluators = make(map[MacroID]*MacroEvaluator)
				partials[field] = macroEvaluators
			}
			macroEvaluators[id] = evaluator
		}
	}

	return partials, nil
}

// GenPartials - Compiles and generates partial Evaluators
func (r *Rule[T]) GenPartials() error {
	macroPartials, err := r.genMacroPartials()
	if err != nil {
		return err
	}

	for _, field := range r.GetFields() {
		state := NewState(r.Model, field, macroPartials[field], r.ReplacementCtx)
		pEval, _, err := nodeToEvaluator(r.ast.BooleanExpression, state)
		if err != nil {
			return fmt.Errorf("couldn't generate partial for field %s and rule %s: %w", field, r.ID, err)
		}

		pEvalBool, ok := pEval.(*BoolEvaluator[T])
		if !ok {
			return NewTypeError(r.ast.Pos, reflect.Bool)
		}

		if pEvalBool.EvalFnc == nil {
			pEvalBool.EvalFnc = func(ctx *Context[T]) bool {
				return pEvalBool.Value
			}
		}

		r.evaluator.setPartial(field, pEvalBool.EvalFnc)
	}

	return nil
}
