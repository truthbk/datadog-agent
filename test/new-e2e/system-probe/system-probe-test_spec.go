package main

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

const (
	Testsuite   = "testsuite"
	TestDirRoot = "/opt/system-probe-tests"
	Sudo        = "sudo"
)

//const TestDirRoot = "/home/usama.saqib/go/github.com/DataDog/datadog-agent/test/kitchen/site-cookbooks/dd-system-probe-check"

var BaseEnv = map[string]string{
	"DD_SYSTEM_PROBE_BPF_DIR": filepath.Join("/opt/system-probe-tests", "pkg/ebpf/bytecode/build"),
}

type testConfig struct {
	bundle         string
	env            map[string]bool
	filterPackages filterPaths
}

type filterPaths struct {
	paths     []string
	inclusive bool
}

var skipPrebuiltTests = filterPaths{
	paths:     []string{"pkg/collector/corechecks/ebpf/probe"},
	inclusive: false,
}

var runtimeCompiledTests = filterPaths{
	paths: []string{
		"pkg/network/tracer",
		"pkg/network/protocols/http",
		"pkg/collector/corechecks/ebpf/probe",
	},
	inclusive: true,
}

var coreTests = filterPaths{
	paths: []string{
		"pkg/collector/corechecks/ebpf/probe",
		"pkg/network/protocols/http",
	},
	inclusive: true,
}

var fentryTests = filterPaths{
	paths:     skipPrebuiltTests.paths,
	inclusive: false,
}

func pathEmbedded(fullPath, embedded string) bool {
	normalized := fmt.Sprintf("/%s/",
		strings.TrimRight(
			strings.TrimLeft(embedded, "/"),
			"/",
		),
	)

	return strings.Contains(fullPath, normalized)
}

func glob(dir, filename string, filter filterPaths) ([]string, error) {
	var matches []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != filename {
			return nil
		}
		for _, p := range filter.paths {
			if pathEmbedded(path, p) && filter.inclusive {
				matches = append(matches, path)
			} else if !pathEmbedded(path, p) && !filter.inclusive {
				matches = append(matches, path)
			}
		}
		return nil
	})
	if err != nil {
		return []string{}, err
	}

	return matches, nil
}

func generatePacakgeName(file string) string {
	pkg := strings.TrimLeft(
		strings.TrimRight(
			strings.TrimPrefix(
				strings.TrimSuffix(file, Testsuite),
				TestDirRoot,
			),
			"/"),
		"/")

	return pkg
}

func buildCommandArgs(file, bundle string) []string {
	pkg := generatePacakgeName(file)
	junitfilePrefix := strings.ReplaceAll(pkg, "/", "-")
	xmlpath := filepath.Join(
		"/", "junit", bundle,
		fmt.Sprintf("%s.xml", junitfilePrefix),
	)
	jsonpath := filepath.Join(
		"/", "pkgjson", bundle,
		fmt.Sprintf("%s.json", junitfilePrefix),
	)
	args := []string{
		"-E",
		"/go/bin/gotestsum",
		"--format", "dots",
		"--junitfile", xmlpath,
		"--jsonfile", jsonpath,
		"--raw-command", "--",
		"/go/bin/test2json", "-t", "-p", pkg, file, "-test.v", "-test.count=1",
	}

	return args
}

func testPass(config testConfig) {
	matches, _ := glob(TestDirRoot, Testsuite, config.filterPackages)
	fmt.Printf("%s\n------\n", config.bundle)
	for _, file := range matches {
		args := buildCommandArgs(file, config.bundle)

	}
	fmt.Println()
}

func main() {
	testPass(testConfig{
		bundle: "prebuilt",
		env: map[string]bool{
			"DD_ENABLE_RUNTIME_COMPILER": false,
			"DD_ENABLE_CO_RE":            false,
		},
		filterPackages: skipPrebuiltTests,
	})
	testPass(testConfig{
		bundle: "runtime",
		env: map[string]bool{
			"DD_ENABLE_RUNTIME_COMPILER":    true,
			"DD_ALLOW_PRECOMPILED_FALLBACK": false,
			"DD_ENABLE_CO_RE":               false,
		},
		filterPackages: runtimeCompiledTests,
	})
	testPass(testConfig{
		bundle: "co-re",
		env: map[string]bool{
			"DD_ENABLE_CO_RE":                    true,
			"DD_ENABLE_RUNTIME_COMPILER":         false,
			"DD_ALLOW_RUNTIME_COMPILED_FALLBACK": false,
			"DD_ALLOW_PRECOMPILED_FALLBACK":      false,
		},
		filterPackages: coreTests,
	})
	testPass(testConfig{
		bundle: "fentry",
		env: map[string]bool{
			"ECS_FARGATE":                   true,
			"DD_ENABLE_CO_RE":               true,
			"DD_ENABLE_RUNTIME_COMPILER":    false,
			"DD_ALLOW_PRECOMPILED_FALLBACK": false,
		},
		filterPackages: fentryTests,
	})
}
