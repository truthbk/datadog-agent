// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package agent

import (
	"encoding/json"
	"fmt"

	"github.com/DataDog/datadog-agent/test/new-e2e/windows"

	"golang.org/x/crypto/ssh"
)

func GetStatus(client *ssh.Client) (map[string]any, error) {
	cmd := fmt.Sprintf("& \"$env:ProgramFiles\\Datadog\\Datadog Agent\\bin\\agent.exe\" status --json")
	output, err := windows.PsExec(client, cmd)
	if err != nil {
		fmt.Println(output)
		return nil, err
	}

	var result map[string]any
	err = json.Unmarshal([]byte(output), &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func GetVersion(client *ssh.Client) (string, error) {
	cmd := fmt.Sprintf("& \"$env:ProgramFiles\\Datadog\\Datadog Agent\\bin\\agent.exe\" version")
	output, err := windows.PsExec(client, cmd)
	if err != nil {
		fmt.Println(output)
		return "", err
	}

	return output, nil
}
