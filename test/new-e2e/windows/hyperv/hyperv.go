// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package hyperv

import (
	"fmt"
	"os/exec"
)

func RevertVM(vm string, snapshot string) error {
	cmdline := fmt.Sprintf("Start-Process -wait -verb runas -FilePath 'powershell' -ArgumentList \"Restore-VMSnapshot -VMName '%s' -Name '%s' -Confirm:`$False\"", vm, snapshot)
	cmd := exec.Command("powershell.exe", cmdline)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(output))
		return err
	}
	return nil
}
