// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package installertest

import (
	"fmt"

	"github.com/DataDog/datadog-agent/test/new-e2e/windows"
	"github.com/DataDog/datadog-agent/test/new-e2e/windows/installer"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

type Tester struct {
	hostname string

	installUser     string
	installPassword string

	username    string
	userdomain  string
	serviceuser string

	expectedAllowClosedSource string
}

type TesterOption func(*Tester)

func NewTester(client *ssh.Client, options ...TesterOption) (*Tester, error) {
	var t Tester

	var err error

	t.hostname, err = windows.GetHostname(client)
	if err != nil {
		return nil, err
	}

	t.username = "ddagentuser"
	t.userdomain = t.hostname
	t.serviceuser = ".\\ddagentuser"

	t.expectedAllowClosedSource = installer.AllowClosedSourceNo

	t.SetOptions(options...)

	return &t, nil
}

func WithInstallUser(user string) TesterOption {
	return func(t *Tester) {
		t.installUser = user
	}
}

func WithInstallPassword(password string) TesterOption {
	return func(t *Tester) {
		t.installPassword = password
	}
}

func WithExpectedAgentUser(domain string, username string, serviceuser string) TesterOption {
	return func(t *Tester) {
		t.username = username
		t.userdomain = domain
		t.serviceuser = serviceuser
	}
}

func WithExpectedAllowClosedSource(val string) TesterOption {
	return func(t *Tester) {
		t.expectedAllowClosedSource = val
	}
}

func (t *Tester) SetOptions(options ...TesterOption) {
	for _, o := range options {
		o(t)
	}
}

func (t *Tester) assertAgentUser(a *assert.Assertions, client *ssh.Client) bool {
	return AssertInstalledUser(a, client, t.username, t.userdomain, t.serviceuser)
}

func (t *Tester) assertAllowClosedSource(a *assert.Assertions, client *ssh.Client) bool {
	return AssertAllowClosedSource(a, client, t.expectedAllowClosedSource)
}

func (t *Tester) assertServices(a *assert.Assertions, client *ssh.Client) bool {
	svcs := []struct {
		name      string
		starttype int
		status    int
	}{
		{"datadogagent", windows.SERVICE_AUTO_START, windows.SERVICE_RUNNING},
		// TODO: figure out why trace-agent is sometimes running and sometimes not
		// {"datadog-trace-agent", windows.SERVICE_DEMAND_START, windows.SERVICE_STOPPED},
		{"datadog-system-probe", windows.SERVICE_DEMAND_START, windows.SERVICE_STOPPED},
		{"datadog-process-agent", windows.SERVICE_DEMAND_START, windows.SERVICE_RUNNING},
	}
	for _, svc := range svcs {
		info, err := windows.GetServiceInfo(client, svc.name)
		if !a.NoError(err) {
			return false
		}
		if !a.Equal(svc.starttype, int(info["StartType"].(float64)), fmt.Sprintf("%s service StartType should be %d", svc.name, svc.starttype)) {
			return false
		}
		if !a.Equal(svc.status, int(info["Status"].(float64)), fmt.Sprintf("%s service Status should be %d", svc.name, svc.status)) {
			return false
		}
	}

	return true
}

func (t *Tester) AssertExpectations(a *assert.Assertions, client *ssh.Client) bool {
	if !t.assertAllowClosedSource(a, client) {
		return false
	}
	if !t.assertAgentUser(a, client) {
		return false
	}
	if !t.assertServices(a, client) {
		return false
	}
	return true
}

func (t *Tester) InstallAgent(client *ssh.Client, installerpath string, args string, logfile string) error {
	if t.installUser != "" {
		args = args + fmt.Sprintf(" DDAGENTUSER_NAME=%s", t.installUser)
	}
	if t.installPassword != "" {
		args = args + fmt.Sprintf(" DDAGENTUSER_PASSWORD=%s", t.installPassword)
	}

	err := installer.InstallAgent(client, installerpath, args, logfile)
	return err
}
