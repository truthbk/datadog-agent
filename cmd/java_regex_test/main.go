package main

import (
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/DataDog/datadog-agent/pkg/process/monitor"
)

func main() {
	mon := monitor.GetProcessMonitor()
	cleanup, err := mon.Subscribe(&monitor.ProcessCallback{
		Event:    monitor.EXEC,
		Metadata: monitor.NAME,
		Regex:    regexp.MustCompile(os.Getenv("SYSPROBE_JAVA_REGEX")),
		Callback: func(pid uint32) {
			fmt.Printf("New Java Process with pid %q\n", pid)
		},
	})
	if err != nil {
		log.Fatalf("process monitor Subscribe() error: %s", err)
	}

	cleanup()
}
