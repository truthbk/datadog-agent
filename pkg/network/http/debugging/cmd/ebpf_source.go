//go:build linux_bpf
// +build linux_bpf

package main

import (
	_ "embed"
	"os"
	"path"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

//go:embed http-debug.o
var bytecode []byte

func setupBytecode() {
	f, err := os.Create(path.Join(bytecodeDir(), "http-debug.o"))
	checkError(err)
	_, err = f.Write(bytecode)
	checkError(err)
	log.Debugf("writing temporary debugging ebpf bytecode to %s", f.Name())
}

func teardownBytecode() {
	os.Remove(path.Join(bytecodeDir(), "http-debug.o"))
}

func bytecodeDir() string {
	if dir := os.Getenv("HTTP_DEBUGGER_BPF_DIR"); dir != "" {
		return dir
	}

	return os.TempDir()
}
