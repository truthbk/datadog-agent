// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/btf"
	"github.com/pmezard/go-difflib/difflib"

	"github.com/DataDog/datadog-agent/pkg/util/kernel"
)

var versionRegex = regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+))?.*$`)

type btfFile struct {
	v        kernel.Version
	path     string
	filename string
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("path to archive directory and function name required")
	}

	arch := runtime.GOARCH
	if len(os.Args) > 2 {
		arch = os.Args[2]
	}
	var btfhubArch string
	switch arch {
	case "arm64":
		btfhubArch = "arm64"
	case "amd64":
		btfhubArch = "x86_64"
	}

	archivePath := os.Args[1]
	searchDir := fmt.Sprintf("%s/*/*/%s/*.btf", archivePath, btfhubArch)

	searchType := os.Args[3]
	switch searchType {
	case "func":
		funcName := os.Args[4]
		searchForChanges(searchDir, funcSearchFunc(funcName), false, false)
	case "member":
		memberPath := os.Args[4]
		searchForChanges(searchDir, memberSearchFunc(memberPath), false, false)
	case "type":
		typeName := os.Args[4]
		searchForChanges(searchDir, typeSearchFunc(typeName), false, true)
	default:
		log.Fatalf("unknown search type: %s\n", searchType)
	}
}

func searchForChanges(searchDir string, searchFunc changeFunc, fullSearch bool, diff bool) {
	fmt.Printf("searching %s for BTF\n", searchDir)
	btfPaths, err := filepath.Glob(searchDir)
	if err != nil {
		log.Fatal(err)
	}

	var btfs []btfFile
	for _, b := range btfPaths {
		filename := strings.TrimSuffix(filepath.Base(b), ".btf")
		kv, err := parseReleaseString(filename)
		if err != nil {
			log.Printf("unable to parse filename %s: %s", filename, err)
			continue
		}
		btfs = append(btfs, btfFile{v: kv, path: b, filename: filename})
	}
	sort.SliceStable(btfs, func(i, j int) bool {
		return btfs[i].v < btfs[j].v
	})
	if len(btfs) < 2 {
		log.Fatalf("found less than two valid BTFs")
		return
	}

	fmt.Printf("examining kernels from %s to %s\n", btfs[0].v, btfs[len(btfs)-1].v)
	search(btfs, searchFunc, fullSearch, diff)
}

type changeFunc func(*btf.Spec) (string, error)

func search(btfs []btfFile, searchFunc changeFunc, fullSearch bool, diff bool) {
	var lastSig string
	var lastV kernel.Version
	for _, b := range btfs {
		if !fullSearch && (b.v == lastV || (b.v.Major() == lastV.Major() && b.v.Minor() == lastV.Minor())) {
			continue
		}

		s, err := btf.LoadSpec(b.path)
		if err != nil {
			log.Printf("unable to load btf spec from %s: %s", b, err)
			continue
		}
		sig, err := searchFunc(s)
		if err != nil {
			fmt.Printf("%13s%s:\terror searching: %s\n", "", fv(b.v), err)
			lastV = b.v
			lastSig = ""
			continue
		}

		if sig != lastSig {
			if b.v.Major() != lastV.Major() || (b.v.Minor()-1 != lastV.Minor()) {
				fmt.Printf("%s - %s:\t", fv(lastV), fv(b.v))
			} else {
				fmt.Printf("%13s%s:\t", "", fv(b.v))
			}

			if diff {
				diffstr, err := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
					A:        difflib.SplitLines(lastSig),
					FromFile: lastV.String(),
					B:        difflib.SplitLines(sig),
					ToFile:   b.v.String(),
					Context:  2,
				})
				if err != nil {
					fmt.Printf("%13s%s:\terror diffing: %s\n", "", fv(b.v), err)
				}
				fmt.Printf("\n%s\n", diffstr)
			} else {
				fmt.Printf("%s\n", sig)
			}
			lastSig = sig
		}
		if b.v != lastV {
			//fmt.Printf("%s [%s]\n", b.filename, b.v)
			lastV = b.v
		}
	}
}

func funcSearchFunc(funcName string) changeFunc {
	return func(s *btf.Spec) (string, error) {
		var ft *btf.Func
		err := s.TypeByName(funcName, &ft)
		if err != nil {
			return "", err
		}
		sig := formatFunc(ft)
		return sig, nil
	}
}

func typeSearchFunc(typeName string) changeFunc {
	return func(s *btf.Spec) (string, error) {
		rs, err := firstStruct(s, typeName)
		if err != nil {
			return "", err
		}

		return describeStruct(rs), nil
	}
}

func describeUnion(rs *btf.Union, indent int) string {
	var sb strings.Builder
	for i := 0; i < indent; i++ {
		sb.WriteRune('\t')
	}
	sb.WriteString("union")
	if len(rs.Name) > 0 {
		sb.WriteRune(' ')
		sb.WriteString(rs.Name)
	}
	sb.WriteString(" {\n")
	for _, m := range rs.Members {
		for i := 0; i <= indent; i++ {
			sb.WriteRune('\t')
		}
		sb.WriteString(formatParam(m.Name, m.Type))
		sb.WriteRune(';')
		sb.WriteRune('\n')
	}
	for i := 0; i < indent; i++ {
		sb.WriteRune('\t')
	}
	sb.WriteString("}")
	return sb.String()
}

func describeStruct(rs *btf.Struct) string {
	var sb strings.Builder
	sb.WriteString("\nstruct ")
	sb.WriteString(rs.Name)
	sb.WriteString(" {\n")
	for _, m := range rs.Members {
		switch v := m.Type.(type) {
		case *btf.Union:
			sb.WriteString(describeUnion(v, 1))
		default:
			sb.WriteRune('\t')
			sb.WriteString(formatParam(m.Name, m.Type))
		}
		sb.WriteRune(';')
		sb.WriteRune('\n')
	}
	sb.WriteString("}\n")
	return sb.String()
}

func searchTypeForMember(t btf.Type, name string) (btf.Type, []uint32) {
	switch v := t.(type) {
	case *btf.Union:
		for _, m := range v.Members {
			//fmt.Printf("%s->%s\n", v.Name, m.Name)
			if m.Name == name {
				return m.Type, []uint32{m.Offset.Bytes()}
			} else if m.Name == "" {
				//fmt.Printf("searching anonymous union under %s\n", v.Name)
				found, off := searchTypeForMember(m.Type, name)
				if found != nil {
					return found, append([]uint32{m.Offset.Bytes()}, off...)
				}
			}
		}
	case *btf.Struct:
		for _, m := range v.Members {
			//fmt.Printf("%s->%s\n", v.Name, m.Name)
			if m.Name == name {
				return m.Type, []uint32{m.Offset.Bytes()}
			} else if m.Name == "" {
				//fmt.Printf("searching anonymous struct under %s\n", v.Name)
				found, off := searchTypeForMember(m.Type, name)
				if found != nil {
					return found, append([]uint32{m.Offset.Bytes()}, off...)
				}
			}
		}
	}
	return nil, nil
}

func firstStruct(s *btf.Spec, name string) (*btf.Struct, error) {
	typs, err := s.AnyTypesByName(name)
	if err != nil {
		return nil, err
	}
	for _, t := range typs {
		switch v := t.(type) {
		case *btf.Struct:
			return v, nil
		default:
			continue
		}
	}
	return nil, fmt.Errorf("unable to find struct named %s", name)
}

func memberSearchFunc(typeName string) changeFunc {
	return func(s *btf.Spec) (string, error) {
		parts := strings.Split(typeName, ".")
		if len(parts) < 2 {
			return "", fmt.Errorf("struct field must be specified")
		}
		rs, err := firstStruct(s, parts[0])
		if err != nil {
			return "", err
		}

		fields := parts[1:]
		var root btf.Type = rs
		var offsets []string
		var totalOffset uint32
		for i, f := range fields {
			nr, off := searchTypeForMember(root, f)
			if nr == nil {
				return "", fmt.Errorf("unable to find member %s", f)
			}
			for _, o := range off {
				offsets = append(offsets, fmt.Sprintf("%d", o))
				totalOffset += o
			}

			if i < len(fields)-1 {
				switch nr.(type) {
				case *btf.Struct:
				case *btf.Union:
				default:
					return "", fmt.Errorf("member %s does not have members", f)
				}
			}
			root = nr
		}
		if len(offsets) == 1 {
			return fmt.Sprintf("%d bytes", totalOffset), nil
		}
		return fmt.Sprintf("%s=%d bytes", strings.Join(offsets, "+"), totalOffset), nil
	}
}

func fv(v kernel.Version) string {
	return fmt.Sprintf("%10s", fmt.Sprintf("[%s]", v))
}

func formatFunc(f *btf.Func) string {
	fp, ok := f.Type.(*btf.FuncProto)
	if !ok {
		return "unknown func type"
	}
	var sb strings.Builder
	sb.WriteString(f.Linkage.String())
	sb.WriteRune(' ')
	sb.WriteString(formatFuncProto(f.Name, fp))
	return sb.String()
}

func formatFuncProto(name string, fp *btf.FuncProto) string {
	var sb strings.Builder
	sb.WriteString(formatParam("", fp.Return))
	sb.WriteString(name)
	sb.WriteRune('(')
	for i, p := range fp.Params {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(formatParam(p.Name, p.Type))
	}
	sb.WriteRune(')')
	return sb.String()
}

func formatParam(name string, p btf.Type) string {
	switch v := p.(type) {
	case *btf.Pointer:
		switch v.Target.(type) {
		case *btf.FuncProto:
			return formatParam(name, v.Target)
		default:
			return formatParam(fmt.Sprintf("*%s", name), v.Target)
		}
	case *btf.Struct:
		return fmt.Sprintf("struct %s %s", v.Name, name)
	case *btf.Int:
		return fmt.Sprintf("%s %s", v.Name, name)
	case *btf.Void:
		return fmt.Sprintf("void %s", name)
	case *btf.FuncProto:
		return formatFuncProto(name, v)
	case *btf.Const:
		return fmt.Sprintf("const %s", formatParam(name, v.Type))
	case *btf.Typedef:
		// don't follow typedef
		return fmt.Sprintf("%s %s", v.Name, name)
	case *btf.Array:
		return fmt.Sprintf("%s[%d]", formatParam(name, v.Type), v.Nelems)
	case *btf.Fwd:
		return fmt.Sprintf("%s %s %s", v.Kind.String(), v.Name, name)
	default:
		return fmt.Sprintf("%v %s", v, name)
	}
}

func parseReleaseString(releaseString string) (kernel.Version, error) {
	versionParts := versionRegex.FindStringSubmatch(releaseString)
	if len(versionParts) < 3 {
		return 0, fmt.Errorf("got invalid release version %q (expected format '4.3.2-1')", releaseString)
	}
	var major, minor, patch uint64
	var err error
	major, err = strconv.ParseUint(versionParts[1], 10, 8)
	if err != nil {
		return 0, err
	}

	minor, err = strconv.ParseUint(versionParts[2], 10, 8)
	if err != nil {
		return 0, err
	}

	// patch is optional
	if len(versionParts) >= 4 {
		patch, _ = strconv.ParseUint(versionParts[3], 10, 8)
	}

	return kernel.VersionCode(byte(major), byte(minor), byte(patch)), nil
}
