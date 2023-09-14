// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package offsetguess

import (
	"fmt"
	"reflect"
	"time"

	"golang.org/x/exp/slices"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type guessField[V, O any] struct {
	what          GuessWhat
	subject       GuessSubject
	finished      bool
	optional      bool
	valueFields   []reflect.StructField
	valueSize     uint64
	offsetField   *uint64
	startOffset   *uint64
	threshold     uint64
	equalFunc     func(field *guessField[V, O], val *V, exp *V) bool
	incrementFunc func(field *guessField[V, O], offsets *O, errored bool)
	nextFunc      func(field *guessField[V, O], allFields *guessFields[V, O], equal bool) GuessWhat
}

type guessFields[V, O any] []guessField[V, O]

func (gf guessFields[V, O]) subjectFields(sub GuessSubject) []*guessField[V, O] {
	var sf []*guessField[V, O]
	for i, f := range gf {
		if f.subject != sub {
			continue
		}
		sf = append(sf, &gf[i])
	}
	return sf
}

func (gf guessFields[V, O]) whatField(what GuessWhat) *guessField[V, O] {
	fieldIndex := slices.IndexFunc(gf, func(field guessField[V, O]) bool {
		return field.what == what
	})
	if fieldIndex == -1 {
		return nil
	}

	return &gf[fieldIndex]
}

func (gf guessFields[V, O]) fixup(threshold uint64) error {
	// fixup and validate guess fields
	for i := range gf {
		f := &gf[i]
		if f.offsetField == nil {
			return fmt.Errorf("guessField %s has no valid offsetField", f.what)
		}
		if f.valueSize == 0 && len(f.valueFields) > 0 {
			f.valueSize = uint64(f.valueFields[0].Type.Size())
		}
		if f.valueSize == 0 {
			return fmt.Errorf("`%s` has value field size 0", f.what)
		}
		if f.threshold == 0 {
			f.threshold = threshold
		}
		if f.equalFunc == nil {
			if len(f.valueFields) == 0 {
				return fmt.Errorf("`%s` needs a valid `valueFields` to use default equality function", f.what)
			}
			f.equalFunc = dfaultEqualFunc[V, O]
		}
		if f.incrementFunc == nil {
			f.incrementFunc = dfaultIncrementFunc[V, O]
		}
		if f.nextFunc == nil {
			f.nextFunc = advanceField[V, O](1)
		}
	}
	return nil
}

func (gf guessFields[V, O]) logAndAdvance(state *GuessState, offset uint64, next GuessWhat) error {
	guess := GuessWhat(state.What)
	if offset != notApplicable {
		log.Debugf("Successfully guessed `%s` with offset of %d bytes", guess, offset)
	} else {
		log.Debugf("Could not guess offset for %s", guess)
	}

	if next == GuessNotApplicable {
		state.State = uint64(StateReady)
		return nil
	}

	log.Debugf("Started offset guessing for %s", next)
	state.What = uint64(next)
	state.State = uint64(StateChecking)

	// check initial offset for next field and jump past overlaps
	nextField := gf.whatField(next)
	if nextField == nil {
		return fmt.Errorf("invalid offset guessing field %d", state.What)
	}
	if nextField.startOffset != nil {
		*nextField.offsetField = *nextField.startOffset
	}
	_ = nextField.jumpPastOverlaps(gf.subjectFields(nextField.subject))
	return nil
}

func dfaultEqualFunc[V, O any](field *guessField[V, O], val *V, exp *V) bool {
	for _, vf := range field.valueFields {
		valueField := reflect.Indirect(reflect.ValueOf(val)).FieldByIndex(vf.Index)
		expectedField := reflect.Indirect(reflect.ValueOf(exp)).FieldByIndex(vf.Index)
		if !valueField.Equal(expectedField) {
			return false
		}
	}
	return true
}

func dfaultIncrementFunc[V, O any](field *guessField[V, O], _ *O, _ bool) {
	*field.offsetField++
}

func advanceField[V, O any](n int) func(field *guessField[V, O], allFields *guessFields[V, O], _ bool) GuessWhat {
	return func(field *guessField[V, O], allFields *guessFields[V, O], _ bool) GuessWhat {
		fieldIndex := slices.IndexFunc(*allFields, func(f guessField[V, O]) bool {
			return f.what == field.what
		})
		fieldIndex += n
		if fieldIndex >= len(*allFields) {
			return GuessNotApplicable
		}
		return (*allFields)[fieldIndex].what
	}
}

func (field *guessField[V, O]) jumpPastOverlaps(subjectFields []*guessField[V, O]) bool {
	overlapped := false
	for {
		// overlaps only checks for a single field overlap, so we must keep jumping until valid
		nextValid, isOverlapping := field.overlaps(subjectFields)
		if isOverlapping {
			// TODO advancing just a single offset may not be what each field needs
			// it may be multiple offsets in concert
			*field.offsetField = nextValid
			overlapped = true
			if nextValid >= field.threshold {
				return true
			}
			continue
		}
		break
	}
	return overlapped
}

func (field *guessField[V, O]) overlaps(subjectFields []*guessField[V, O]) (uint64, bool) {
	offset := *field.offsetField
	//log.Warnf("`%s` offset %d post", field.what, offset)
	for _, f := range subjectFields {
		if !f.finished || f.what == field.what {
			continue
		}
		soff := *f.offsetField
		size := f.valueSize
		nextValid := soff + size
		if soff <= offset && offset < nextValid {
			log.Debugf("`%s` offset %d overlapping with `%s` offset %d size %d",
				field.what, offset,
				f.what, soff, size)
			return nextValid, true
		}
	}
	return 0, false
}

type offsetGuesser[V, O any] struct {
	state   *GuessState
	fields  guessFields[V, O]
	values  *V
	offsets *O
}

func newOffsetGuesser[V, O any](state *GuessState, values *V, offsets *O) *offsetGuesser[V, O] {
	return &offsetGuesser[V, O]{
		state:   state,
		values:  values,
		offsets: offsets,
	}
}

func (og *offsetGuesser[V, O]) iterate(expected *V, maxRetries *int) error {
	if State(og.state.State) != StateChecked {
		if *maxRetries == 0 {
			return fmt.Errorf("invalid guessing state while guessing %s, got %s expected %s",
				GuessWhat(og.state.What), State(og.state.State), StateChecked)
		}
		*maxRetries--
		time.Sleep(10 * time.Millisecond)
		return nil
	}

	field := og.fields.whatField(GuessWhat(og.state.What))
	if field == nil {
		return fmt.Errorf("invalid offset guessing field %d", og.state.What)
	}

	// check if used offset overlaps. If so, ignore equality because it isn't a valid offset
	// we check after usage, because the eBPF code can adjust the offset due to alignment rules
	overlapped := field.jumpPastOverlaps(og.fields.subjectFields(field.subject))
	if overlapped {
		// skip to checking the newly set offset
		og.state.State = uint64(StateChecking)
		goto NextCheck
	}

	if field.equalFunc(field, og.values, expected) {
		offset := *field.offsetField
		field.finished = true
		next := field.nextFunc(field, &og.fields, true)
		if err := og.fields.logAndAdvance(og.state, offset, next); err != nil {
			return err
		}
		goto NextCheck
	}

	field.incrementFunc(field, og.offsets, og.state.Err != 0)
	og.state.State = uint64(StateChecking)

NextCheck:
	if *field.offsetField >= field.threshold {
		if field.optional {
			next := field.nextFunc(field, &og.fields, false)
			if err := og.fields.logAndAdvance(og.state, notApplicable, next); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("%s overflow: %w", GuessWhat(og.state.What), errOffsetOverflow)
		}
	}

	og.state.Err = 0
	return nil
}
