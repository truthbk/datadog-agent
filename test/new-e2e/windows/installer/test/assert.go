// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package installertest

import (
	"strings"

	"github.com/DataDog/datadog-agent/test/new-e2e/windows"
	"github.com/DataDog/datadog-agent/test/new-e2e/windows/installer"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

func AssertDefaultInstalledUser(a *assert.Assertions, client *ssh.Client) bool {
	// get hostname
	hostinfo, err := windows.GetHostInfo(client)
	if !a.NoError(err) {
		return false
	}
	username, userdomain, serviceuser := installer.DefaultAgentUser(hostinfo)

	return AssertInstalledUser(a, client, username, userdomain, serviceuser)
}

func AssertInstalledUser(a *assert.Assertions, client *ssh.Client, expectedusername string, expecteddomain string, expectedserviceuser string) bool {
	// check registry keys
	username, err := windows.GetRegistryValue(client, "HKLM:\\SOFTWARE\\Datadog\\Datadog Agent", "installedUser")
	if !a.NoError(err) {
		return false
	}
	domain, err := windows.GetRegistryValue(client, "HKLM:\\SOFTWARE\\Datadog\\Datadog Agent", "installedDomain")
	if !a.NoError(err) {
		return false
	}
	domain = strings.ToUpper(domain)
	expecteddomain = strings.ToUpper(expecteddomain)
	if !a.Equal(expectedusername, username, "installedUser registry value should be %s", expectedusername) {
		return false
	}
	if !a.Equal(expecteddomain, domain, "installedDomain registry value should be %s", expecteddomain) {
		return false
	}

	// check service users
	svcs := []struct {
		name    string
		account string
	}{
		{"datadogagent", expectedserviceuser},
		{"datadog-trace-agent", expectedserviceuser},
		{"datadog-system-probe", "LocalSystem"},
		{"datadog-process-agent", "LocalSystem"},
	}
	for _, svc := range svcs {
		user, err := windows.GetServiceAccountName(client, svc.name)
		if !a.NoError(err) {
			return false
		}
		if !a.Equal(svc.account, user, "%s logon account should be %s", svc.name, svc.account) {
			return false
		}
	}

	return true
}
