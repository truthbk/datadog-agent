//go:build linux_bpf
// +build linux_bpf

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	ddconfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/http"
)

var (
	srcPort = flag.Int("src_port", 0, "src port filter")
	dstPort = flag.Int("dst_port", 0, "dst port filter")
	srcAddr = flag.String("src_addr", "", "src addr filter")
	dstAddr = flag.String("dst_addr", "", "dst addr filter")
)

func main() {
	err := ddconfig.SetupLogger(
		"http-debugger",
		"debug",
		"",
		ddconfig.GetSyslogURI(),
		false,
		true,
		false,
	)
	checkError(err)

	setupBytecode()
	defer teardownBytecode()

	monitor, err := http.NewMonitor(getConfiguration(), nil, nil)
	checkError(err)

	err = monitor.Start()
	checkError(err)

	go func() {
		t := time.NewTicker(10 * time.Second)
		for range t.C {
			_ = monitor.GetHTTPStats()
		}
	}()

	defer monitor.Stop()
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	<-done
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(-1)
	}
}

func getConfiguration() *config.Config {
	c := config.New()

	// run debug version of the eBPF program
	c.BPFDebug = true

	// don't buffer data in userspace
	c.MaxHTTPStatsBuffered = 0

	// set BPFDir to the directory created by this program
	// with the embedded debugging eBPF bytecode
	c.BPFDir = bytecodeDir()

	// make sure HTTP monitoring is enabled
	c.EnableHTTPMonitoring = true

	// HTTPS is not supported at the moment because the sockFD mapping depends
	// on the tracer program
	c.EnableHTTPSMonitoring = false

	// configure filters using command line arguments
	flag.Parse()
	c.HTTPFilterSport = *srcPort
	c.HTTPFilterDport = *dstPort
	c.HTTPFilterSaddr = *srcAddr
	c.HTTPFilterDaddr = *dstAddr

	return c
}
