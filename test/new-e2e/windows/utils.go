// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package windows

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

func LocalUserExists(client *ssh.Client, user string) (bool, error) {
	cmd := fmt.Sprintf("(Get-LocalUser).Name -Contains '%s'", user)
	out, err := PsExec(client, cmd)
	if err != nil {
		return false, err
	}
	return out == "True", nil
}

func GetHostname(client *ssh.Client) (string, error) {
	hostname, err := PsExec(client, "[Environment]::MachineName")
	if err != nil {
		return "", err
	}
	return hostname, nil
}
