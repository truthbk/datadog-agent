// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package windows

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"golang.org/x/crypto/ssh"
)

type HostInfo struct {
	Hostname string
	Domain   string
	OSInfo   *OSInfo
}

// Selection of values from: Get-WmiObject Win32_OperatingSystem
// https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem
type OSInfo struct {
	WindowsDirectory string `json:"WindowsDirectory"`
	Version          string `json:"Version"`
	SystemDrive      string `json:"SystemDrive"`
	SystemDirectory  string `json:"SystemDirectory"`
	ProductType      int    `json:"ProductType"`
	OSType           int    `json:"OSType"`
	OSProductSuite   int    `json:"OSProductSuite"`
	OSLanguage       int    `json:"OSLanguage"`
	Locale           string `json:"Locale"`
	BuildNumber      string `json:"BuildNumber"`
	Caption          string `json:"Caption"`
}

func GetHostInfo(client *ssh.Client) (*HostInfo, error) {
	osinfo, err := GetOSInfo(client)
	if err != nil {
		return nil, err
	}
	hostname, err := GetHostname(client)
	if err != nil {
		return nil, err
	}
	domain, err := GetJoinedDomain(client)
	if err != nil {
		return nil, err
	}

	var h HostInfo
	h.Hostname = hostname
	h.Domain = domain
	h.OSInfo = osinfo

	return &h, nil
}

func (h *HostInfo) IsDomainController() bool {
	return h.OSInfo.ProductType == 2
}

func GetHostname(client *ssh.Client) (string, error) {
	hostname, err := PsExec(client, "[Environment]::MachineName")
	if err != nil {
		return "", fmt.Errorf("GetHostname failed: %v", err)
	}
	return hostname, nil
}

func GetJoinedDomain(client *ssh.Client) (string, error) {
	domain, err := PsExec(client, "(Get-WMIObject Win32_ComputerSystem).Domain")
	if err != nil {
		return "", fmt.Errorf("GetJoinedDomain failed: %v", err)
	}
	return domain, nil
}

func GetOSInfo(client *ssh.Client) (*OSInfo, error) {
	cmd := fmt.Sprintf("Get-WmiObject Win32_OperatingSystem | ConvertTo-Json")
	output, err := PsExec(client, cmd)
	if err != nil {
		fmt.Println(output)
		return nil, fmt.Errorf("GetOSInfo failed: %v", err)
	}

	var result OSInfo
	err = json.Unmarshal([]byte(output), &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func NetBIOSName(name string) string {
	parts := strings.Split(name, ".")
	upper := strings.ToUpper(parts[0])
	maxlen := int(math.Min(float64(len(upper)), 15))
	return upper[:maxlen]
}
