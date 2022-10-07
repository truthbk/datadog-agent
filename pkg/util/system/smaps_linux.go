// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package system

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	procSMapsHeaderLine = regexp.MustCompile(`^[a-f0-9].*$`)
)

// readFileNoStat uses io.ReadAll to read contents of entire file.
// This is similar to os.ReadFile but without the call to os.Stat, because
// many files in /proc and /sys report incorrect file sizes (either 0 or 4096).
// Reads a max file size of 1024kB.  For files larger than this, a scanner
// should be used.
// COPIED FROM prometheus/procfs, proc/self/smaps can almost certainly be over 1024kb, so this should be replaced
func readFileNoStat(filename string) ([]byte, error) {
	const maxBufferSize = 1024 * 1024

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := io.LimitReader(f, maxBufferSize)
	return io.ReadAll(reader)
}

func parseMapLine(smap *SmapData, line string) error {
	kv := strings.SplitN(line, ":", 2)
	if len(kv) != 2 {
		fmt.Println(line)
		return errors.New("invalid proc/self/smaps line, missing colon")
	}

	k := kv[0]
	if k == "VmFlags" {
		return nil
	}

	v := strings.TrimSpace(kv[1])
	v = strings.TrimRight(v, " kB")

	vKBytes, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return err
	}
	vBytes := vKBytes * 1024

	addValue(smap, k, vKBytes, vBytes)

	return nil
}

func addValue(smap *SmapData, k string, vUint uint64, vUintBytes uint64) {
	switch k {
	case "Rss":
		smap.Rss += vUintBytes
	case "Pss":
		smap.Pss += vUintBytes
	case "Shared_Clean":
		smap.SharedClean += vUintBytes
	case "Shared_Dirty":
		smap.SharedDirty += vUintBytes
	case "Private_Clean":
		smap.PrivateClean += vUintBytes
	case "Private_Dirty":
		smap.PrivateDirty += vUintBytes
	case "Referenced":
		smap.Referenced += vUintBytes
	case "Anonymous":
		smap.Anonymous += vUintBytes
	case "Swap":
		smap.Swap += vUintBytes
	case "SwapPss":
		smap.SwapPss += vUintBytes
	}
}

func GetSelfSmapStats(procPath string) (SelfMemStats, error) {
	path := filepath.Join(procPath, "self", "smaps")

	data, err := readFileNoStat(path)
	if err != nil && os.IsNotExist(err) {
		return nil, fmt.Errorf("%s does not exist", path)
	}

	lines := strings.Split(string(data), "\n")
	smaps := map[string]SmapData{}

	currentObject := ""
	for _, line := range lines {
		if line == "" {
			continue
		}

		if isHeader, obj := isHeaderLine(line); isHeader {
			currentObject = obj
		} else if currentObject != "" {
			smap := smaps[currentObject]
			err := parseMapLine(&smap, line)
			smaps[currentObject] = smap
			if err != nil {
				fmt.Printf("Error while parsing mem line %q: %v", line, err)
			}
		} else if currentObject == "" {
			fmt.Printf("Uh-oh, empty object!")
		}
	}

	return smaps, nil
}

func isHeaderLine(line string) (bool, string) {
	if procSMapsHeaderLine.MatchString(line) {
		tokens := strings.Split(line, " ")
		objName := tokens[len(tokens)-1]
		if objName == "" {
			// https://stackoverflow.com/questions/2787241/smaps-un-named-segment-of-memory
			objName = "mmap_anonymous"
		}
		return true, objName

	}
	return false, ""
}
