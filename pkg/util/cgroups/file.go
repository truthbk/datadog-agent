// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package cgroups

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	spaceSeparator = " "
)

var defaultFileReader = &osFileReader{}

type fileReader interface {
	open(path string) (file, error)
}

type file interface {
	io.Reader
	Close() error
}

type osFileReader struct{}

func (fr *osFileReader) open(path string) (file, error) {
	reportFileAccessed(path)
	return os.Open(path)
}

type stopParsingError struct{}

func (e *stopParsingError) Error() string {
	return "stopping file parsing" // should never be used
}

// returning an error will stop parsing and return the error
// with the exception of stopParsingError that will return without error
//
// the input to parser is a byte representing a line without whitespace. The contents of the given
// slice might be overwritten after parser() runs.
type parser func([]byte) error

func parseFile(fr fileReader, path string, p parser) error {
	f, err := fr.open(path)
	if err != nil {
		return newFileSystemError(path, err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Bytes()
		err := p(line)
		if err != nil {
			if errors.Is(err, &stopParsingError{}) {
				return nil
			}

			return err
		}

	}
	if s.Err() != io.EOF {
		return s.Err()
	}

	return nil
}

var (
	bytesMax = []byte("max")
)

func parseSingleSignedStat(fr fileReader, path string, val **int64) error {
	return parseFile(fr, path, func(lineRaw []byte) error {
		// handle cgroupv2 max value, we usually consider max == no value (limit)
		if bytes.Equal(lineRaw, bytesMax) {
			return &stopParsingError{}
		}

		line := string(lineRaw)
		value, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			return newValueError(line, err)
		}
		*val = &value
		return &stopParsingError{}
	})
}

func parseSingleUnsignedStat(fr fileReader, path string, val **uint64) error {
	fmt.Printf("parsed single unsighted %s\n", path)
	return parseFile(fr, path, func(lineRaw []byte) error {

		fmt.Printf("%s", string(lineRaw))
		// handle cgroupv2 max value, we usually consider max == no value (limit)
		if bytes.Equal(lineRaw, bytesMax) {
			return &stopParsingError{}
		}

		line := string(lineRaw)
		value, err := strconv.ParseUint(line, 10, 64)
		if err != nil {
			return newValueError(line, err)
		}
		*val = &value
		return &stopParsingError{}
	})
}

func parseColumnStats(fr fileReader, path string, valueParser func(*bufio.Scanner) error) error {

	err := parseFile(fr, path, func(line []byte) error {
		scan := bufio.NewScanner(bytes.NewBuffer(line))
		scan.Split(bufio.ScanWords)

		return valueParser(scan)
	})

	return err
}

// columns are 0-indexed, we skip malformed lines
func parse2ColumnStats(fr fileReader, path string, keyColumn, valueColumn int, valueParser func(string, string) error) error {
	fmt.Printf("parse two column stats %s path, %d %d\n", path, keyColumn, valueColumn)
	lastIdx := valueColumn
	if keyColumn > lastIdx {
		lastIdx = keyColumn
	}

	err := parseFile(fr, path, func(line []byte) error {
		fmt.Printf("parsefile line: %s\n", line)
		scan := bufio.NewScanner(bytes.NewBuffer(line)) // TODO: use bufio.ScanWords?
		scan.Split(bufio.ScanWords)

		var keyValue []byte
		var valueValue []byte
		for i := 0; i < keyColumn+1 || i < valueColumn+1; i++ {
			if !scan.Scan() {
				panic("error here") // TODO
			}

			if i == keyColumn {
				keyValue = scan.Bytes()
			}

			if i == valueColumn {
				valueValue = scan.Bytes()
			}
		}

		if len(keyValue) == 0 && len(valueValue) == 0 {
			fmt.Printf("no match! <%s , %s> \n", keyValue, valueValue)
			// TODO - panic?
		}

		fmt.Printf("got %s %s\n", keyValue, valueValue)

		// TODO: convert to strings
		return valueParser(string(keyValue), string(valueValue))
	})

	return err
}

// format is "some avg10=0.00 avg60=0.00 avg300=0.00 total=0"
func parsePSI(fr fileReader, path string, somePsi, fullPsi *PSIStats) error {
	return parseColumnStats(fr, path, func(fieldScan *bufio.Scanner) error {

		var fields [5][]byte
		for i := 0; i < 5; i++ {
			fields[i] = fieldScan.Bytes()
			fieldScan.Scan()
			if fieldScan.Err() != nil && fieldScan.Err() != io.EOF {
				reportError(newValueError("", fmt.Errorf("unexpected format for psi file at: %s, path", path)))
			}
		}

		// TODO: error check

		if len(fields) != 5 {
			reportError(newValueError("", fmt.Errorf("unexpected format for psi file at: %s, line content: %v", path, fields)))
			return nil
		}

		var psiStats *PSIStats

		switch string(fields[0]) { // TODO
		case "some":
			psiStats = somePsi
		case "full":
			psiStats = fullPsi
		default:
			reportError(newValueError("", fmt.Errorf("unexpected psi type (some|full) for psi file at: %s, type: %s", path, fields[0])))
		}

		// User did not provide stat for this type or unknown PSI type
		if psiStats == nil {
			return nil
		}

		for i := 1; i < 5; i++ {
			parts := strings.Split(string(fields[i]), "=") // TODO
			if len(parts) != 2 {
				reportError(newValueError("", fmt.Errorf("unexpected format for psi file at: %s, part: %d, content: %v", path, i, fields[i])))
				continue
			}

			psi, err := strconv.ParseFloat(parts[1], 64)
			if err != nil {
				reportError(newValueError("", fmt.Errorf("unexpected format for psi file at: %s, part: %d, content: %v", path, i, fields[i])))
				continue
			}

			switch parts[0] {
			case "avg10":
				psiStats.Avg10 = &psi
			case "avg60":
				psiStats.Avg60 = &psi
			case "avg300":
				psiStats.Avg300 = &psi
			case "total":
				total, err := strconv.ParseUint(parts[1], 10, 64)
				if err != nil {
					reportError(newValueError("", fmt.Errorf("unexpected format for psi file at: %s, part: %d, content: %v", path, i, fields[i])))
					continue
				}
				psiStats.Total = &total
			}
		}

		return nil
	})
}
