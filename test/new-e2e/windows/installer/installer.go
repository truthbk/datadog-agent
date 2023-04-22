// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package installer

import (
	"fmt"

	"github.com/DataDog/datadog-agent/test/new-e2e/windows"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	AllowClosedSourceNo  = "0"
	AllowClosedSourceYes = "1"
)

func InstallAgent(client *ssh.Client, installer string, args string, logpath string) error {
	sftpclient, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer sftpclient.Close()

	fmt.Printf("Transferring installer...")
	err = windows.PutFile(sftpclient, installer, "C:\\TEMP\\agent.msi")
	if err != nil {
		return err
	}
	fmt.Println("done")

	fmt.Printf("Running installer...")
	output, installerr := windows.PsExec(client, fmt.Sprintf("start-process -wait msiexec.exe -argumentList '/i C:\\TEMP\\agent.msi /qn /l*v C:\\TEMP\\install.log %s'", args))
	if installerr != nil {
		fmt.Println(output)
		// ignore error, we still want to collect the log
	}
	fmt.Println("done")

	fmt.Printf("Collecting installer log...")
	err = windows.GetFile(sftpclient, "C:\\TEMP\\install.log", logpath)
	if err != nil {
		return err
	}
	fmt.Println("done")

	return installerr
}

func GetDatadogAgentProductCode(client *ssh.Client) (string, error) {
	return GetProductCodeByName(client, "Datadog Agent")
}

func GetProductCodeByName(client *ssh.Client, name string) (string, error) {
	cmd := fmt.Sprintf("\"(Get-WmiObject Win32_Product | Where-Object -Property Name -Value '%s' -match).IdentifyingNumber\"", name)
	val, err := windows.PsExec(client, cmd)
	if err != nil {
		fmt.Println(val)
		return "", err
	}
	return val, nil
}

func UninstallAgent(client *ssh.Client, logpath string) error {
	productcode, err := GetDatadogAgentProductCode(client)
	if err != nil {
		return err
	}

	fmt.Printf("Uninstalling %s...", productcode)
	output, uninstallerr := windows.PsExec(client, fmt.Sprintf("start-process -wait msiexec.exe -argumentList /x,'%s',/qn,/l*v,C:\\TEMP\\uninstall.log", productcode))
	if uninstallerr != nil {
		fmt.Println(output)
		// ignore error, we still want to collect the log
	}
	fmt.Println("done")

	sftpclient, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer sftpclient.Close()

	fmt.Printf("Collecting installer log...")
	err = windows.GetFile(sftpclient, "C:\\TEMP\\uninstall.log", logpath)
	if err != nil {
		return err
	}
	fmt.Println("done")

	return uninstallerr
}

func GetAllowClosedSource(client *ssh.Client) (string, error) {
	val, err := windows.GetRegistryValue(client, "HKLM:\\SOFTWARE\\Datadog\\Datadog Agent", "AllowClosedSource")
	if err != nil {
		return "", err
	}
	return val, nil
}
