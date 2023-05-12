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
	hostinfo *windows.HostInfo

	installUser     string
	installPassword string

	username    string
	userdomain  string
	serviceuser string

	expectedNPMRunning        bool
}

type TesterOption func(*Tester)

func NewTester(client *ssh.Client, options ...TesterOption) (*Tester, error) {
	var t Tester

	var err error

	t.hostinfo, err = windows.GetHostInfo(client)
	if err != nil {
		return nil, err
	}

	t.username, t.userdomain, t.serviceuser = installer.DefaultAgentUser(t.hostinfo)

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

func WithExpectedAgentUserFromUsername(client *ssh.Client, username string, password string) TesterOption {
	return func(t *Tester) {
		var domainpart string
		var servicedomainpart string
		if t.hostinfo.IsDomainController() {
			domainpart = windows.NetBIOSName(t.hostinfo.Domain)
			servicedomainpart = windows.NetBIOSName(t.hostinfo.Domain)
			// user must exist on domain controllers
			userexists, err := windows.LocalUserExists(client, username)
			if err == nil && !userexists {
				windows.CreateLocalUser(client, username, password)
				// TODO: return error
			}
		} else {
			domainpart = windows.NetBIOSName(t.hostinfo.Hostname)
			servicedomainpart = "."
		}
		t.username = username
		t.userdomain = domainpart
		t.serviceuser = fmt.Sprintf("%s\\%s", servicedomainpart, username)
	}
}

func WithExpectNPMRunning(val bool) TesterOption {
	return func(t *Tester) {
		t.expectedNPMRunning = val
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

func (t *Tester) assertServices(a *assert.Assertions, client *ssh.Client) bool {
	type expectedService struct {
		name      string
		starttype int
		status    int
		depends   []string
	}

	svcs := []expectedService{
		{"datadogagent", windows.SERVICE_AUTO_START, windows.SERVICE_RUNNING, nil},
		// TODO: figure out why trace-agent is sometimes running and sometimes not
		// {"datadog-trace-agent", windows.SERVICE_DEMAND_START, windows.SERVICE_STOPPED},
		{"datadog-process-agent", windows.SERVICE_DEMAND_START, windows.SERVICE_RUNNING, []string{"datadogagent"}},
	}

	if t.expectedNPMRunning {
		svcs = append(svcs, []expectedService{
			{"ddnpm", windows.SERVICE_DEMAND_START, windows.SERVICE_RUNNING, nil},
			{"datadog-system-probe", windows.SERVICE_DEMAND_START, windows.SERVICE_RUNNING, []string{"datadogagent"}},
		}...)
	} else {
		svcs = append(svcs, []expectedService{
			{"ddnpm", windows.SERVICE_DISABLED, windows.SERVICE_STOPPED, nil},
			{"datadog-system-probe", windows.SERVICE_DEMAND_START, windows.SERVICE_STOPPED, []string{"datadogagent"}},
		}...)
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
		var dependentServices []string
		for _, o := range []any(info["ServicesDependedOn"].([]any)) {
			dep := map[string]any(o.(map[string]any))
			dependentServices = append(dependentServices, string(dep["ServiceName"].(string)))
		}
		if !a.ElementsMatch(svc.depends, dependentServices, "%s should depend on %v", svc.name, svc.depends) {
			return false
		}
	}

	return true
}

func (t *Tester) AssertExpectations(a *assert.Assertions, client *ssh.Client) bool {
	fmt.Printf("Checking agent user...")
	if !t.assertAgentUser(a, client) {
		return false
	}
	fmt.Println("done")

	fmt.Printf("Checking agent services...")
	if !t.assertServices(a, client) {
		return false
	}
	fmt.Println("done")

	return true
}

func (t *Tester) InstallAgent(client *ssh.Client, installerpath string, args string, logfile string) error {
	var err error

	if t.installUser != "" || t.installPassword != "" {
		if t.installUser != "" {
			args = args + fmt.Sprintf(" DDAGENTUSER_NAME=%s", t.installUser)
		}
		if t.installPassword != "" {
			args = args + fmt.Sprintf(" DDAGENTUSER_PASSWORD=%s", t.installPassword)
		}
		err = installer.InstallAgent(client, installerpath, args, logfile)
	} else {
		err = installer.InstallAgentWithDefaultUser(client, installerpath, args, logfile)
	}

	return err
}
