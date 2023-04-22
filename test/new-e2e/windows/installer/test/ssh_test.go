// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package installertest

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/test/new-e2e/windows"
	"github.com/DataDog/datadog-agent/test/new-e2e/windows/hyperv"
	"github.com/DataDog/datadog-agent/test/new-e2e/windows/installer"

	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/ssh"
)

type testHost struct {
	host     string
	username string
	password string
	vmname   string
	snapshot string
}

type windowsInstallerSuite struct {
	suite.Suite

	target *testHost

	installer           string
	prevstableinstaller string

	sshclient *ssh.Client

	// test suite output dir
	suiteoutputdir string
	// individual test output dir
	testoutputdir string
}

func TestWindowsInstaller(t *testing.T) {

	// TODO: make all this configurable
	// TODO: use new-e2e/pulumi for provisioning
	prevstableinstaller := "ddagent-cli-7.43.1.msi"
	testinstaller := "datadog-agent-ng-7.45.0-rc.1.git.23.f274ee9.pipeline.15137088-1-x86_64.msi"
	h := testHost{
		host:     "172.23.224.26:22",
		username: "user",
		password: "user",
		vmname:   "Windows 10",
		snapshot: "ssh",
	}

	suite.Run(t, &windowsInstallerSuite{
		target:              &h,
		suiteoutputdir:      filepath.Join("./output", time.Now().Format(time.RFC3339)),
		prevstableinstaller: prevstableinstaller,
		installer:           testinstaller,
	})
}

func (s *windowsInstallerSuite) SetupSuite() {
	// create output dir
	os.MkdirAll(s.suiteoutputdir, os.ModePerm)
}

func (s *windowsInstallerSuite) SetupTest() {
	// create output dir
	s.testoutputdir = filepath.Join(s.suiteoutputdir, s.T().Name())
	os.MkdirAll(s.testoutputdir, os.ModePerm)

	// revert VM
	fmt.Println("Reverting VM")
	err := hyperv.RevertVM(s.target.vmname, s.target.snapshot)
	s.Require().NoError(err)

	// connect to SSH
	sshconfig := &ssh.ClientConfig{
		User: s.target.username,
		Auth: []ssh.AuthMethod{
			ssh.Password(s.target.password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	sshclient, err := ssh.Dial("tcp", s.target.host, sshconfig)
	s.Require().NoError(err)

	s.sshclient = sshclient
	s.T().Cleanup(func() {
		fmt.Println("closing ssh")
		s.sshclient.Close()
	})

	output, err := windows.PsExec(s.sshclient, "ipconfig")
	s.Require().NoError(err)
	s.Require().NotEmpty(output)
	fmt.Println(output)
}

func (s *windowsInstallerSuite) TestDefaultInstall() {
	t, err := NewTester(s.sshclient)
	s.Require().NoError(err)

	err = t.InstallAgent(s.sshclient, s.installer, "",
		filepath.Join(s.testoutputdir, "install.log"))
	s.Require().NoError(err)

	s.Require().True(t.AssertExpectations(s.Assert(), s.sshclient))
}

func (s *windowsInstallerSuite) TestUninstall() {
	t, err := NewTester(s.sshclient)
	s.Require().NoError(err)

	err = t.InstallAgent(s.sshclient, s.installer, "",
		filepath.Join(s.testoutputdir, "install.log"))
	s.Require().NoError(err)

	s.Require().True(t.AssertExpectations(s.Assert(), s.sshclient))

	err = installer.UninstallAgent(s.sshclient,
		filepath.Join(s.testoutputdir, "uninstall.log"))
	s.Require().NoError(err)

	userexists, err := windows.LocalUserExists(s.sshclient, "ddagentuser")
	s.Require().NoError(err)
	s.Require().True(userexists, "user should still exist after uninstall")
}

func (s *windowsInstallerSuite) TestAllowClosedSourceArgs() {
	tcs := []struct {
		testname string
		args     string
		expected string
	}{
		{"AllowClosedSource1", "ALLOWCLOSEDSOURCE=1", installer.AllowClosedSourceYes},
		{"NpmFlag", "NPM=1", installer.AllowClosedSourceYes},
		{"ADDLOCAL_NPM", "ADDLOCAL=NPM", installer.AllowClosedSourceYes},
	}

	for _, tc := range tcs {
		s.Run(tc.testname, func() {
			s.SetupTest()

			t, err := NewTester(s.sshclient,
				WithExpectedAllowClosedSource(tc.expected))
			s.Require().NoError(err)

			err = t.InstallAgent(s.sshclient, s.installer, tc.args,
				filepath.Join(s.testoutputdir, "install.log"))
			s.Require().NoError(err)

			s.Require().True(t.AssertExpectations(s.Assert(), s.sshclient))
		})
	}
}

func (s *windowsInstallerSuite) TestUpgradeWithNPM() {
	err := installer.InstallAgent(s.sshclient, s.prevstableinstaller, "ADDLOCAL=NPM",
		filepath.Join(s.testoutputdir, "install.log"))
	s.Require().NoError(err)

	t, err := NewTester(s.sshclient,
		WithExpectedAllowClosedSource(installer.AllowClosedSourceYes))
	s.Require().NoError(err)

	err = t.InstallAgent(s.sshclient, s.installer, "",
		filepath.Join(s.testoutputdir, "upgrade.log"))
	s.Require().NoError(err)

	s.Require().True(t.AssertExpectations(s.Assert(), s.sshclient))
}

func (s *windowsInstallerSuite) TestDisableAllowClosedSource() {
	err := installer.InstallAgent(s.sshclient,
		s.prevstableinstaller, "ADDLOCAL=NPM",
		filepath.Join(s.testoutputdir, "install.log"))
	s.Require().NoError(err)

	t, err := NewTester(s.sshclient,
		WithExpectedAllowClosedSource(installer.AllowClosedSourceNo))
	s.Require().NoError(err)

	err = t.InstallAgent(s.sshclient,
		s.installer, "ALLOWCLOSEDSOURCE=0",
		filepath.Join(s.testoutputdir, "upgrade.log"))
	s.Require().NoError(err)

	s.Require().True(t.AssertExpectations(s.Assert(), s.sshclient))
}

func (s *windowsInstallerSuite) TestUpgradeChangeUser() {
	hostname, err := windows.GetHostname(s.sshclient)
	s.Require().NoError(err)

	err = installer.InstallAgent(s.sshclient,
		s.prevstableinstaller, "",
		filepath.Join(s.testoutputdir, "install.log"))
	s.Require().NoError(err)

	s.Require().True(AssertDefaultInstalledUser(s.Assert(), s.sshclient))

	username := "testuser"
	t, err := NewTester(s.sshclient,
		WithInstallUser(username),
		WithInstallPassword("123!@#QWEqwe"),
		WithExpectedAgentUser(hostname, username, fmt.Sprintf(".\\%s", username)))
	s.Require().NoError(err)

	err = t.InstallAgent(s.sshclient,
		s.installer, "",
		filepath.Join(s.testoutputdir, "upgrade.log"))
	s.Require().NoError(err)

	s.Require().True(t.AssertExpectations(s.Assert(), s.sshclient))
}

func (s *windowsInstallerSuite) TestAgentUserOnClient() {
	hostname, err := windows.GetHostname(s.sshclient)
	s.Require().NoError(err)

	tcs := []struct {
		testname            string
		username            string
		expecteddomain      string
		expecteduser        string
		expectedserviceuser string
	}{
		{"user_only", "testuser", hostname, "testuser", ".\\testuser"},
		{"dotslash_user", ".\\testuser", hostname, "testuser", ".\\testuser"},
		{"hostname_user", fmt.Sprintf("%s\\testuser", hostname), hostname, "testuser", ".\\testuser"},
		{"LocalSystem", "LocalSystem", "NT AUTHORITY", "SYSTEM", "LocalSystem"},
		{"SYSTEM", "SYSTEM", "NT AUTHORITY", "SYSTEM", "LocalSystem"},
	}

	for _, tc := range tcs {
		s.Run(tc.testname, func() {
			s.SetupTest()

			t, err := NewTester(s.sshclient,
				WithInstallUser(tc.username),
				WithInstallPassword("123!@#QWEqwe"),
				WithExpectedAgentUser(tc.expecteddomain, tc.expecteduser, tc.expectedserviceuser))
			s.Require().NoError(err)

			err = t.InstallAgent(s.sshclient,
				s.installer, "",
				filepath.Join(s.testoutputdir, "install.log"))
			s.Require().NoError(err)

			s.Require().True(t.AssertExpectations(s.Assert(), s.sshclient))
		})
	}
}
