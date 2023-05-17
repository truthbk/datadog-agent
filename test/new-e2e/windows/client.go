// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package windows

import (
	"bytes"
	"os"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func PsExec(client *ssh.Client, command string) (string, error) {
	s, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()

	var outstr string
	out, err := s.CombinedOutput(command)
	if out != nil {
		outstr = strings.TrimSuffix(string(out), "\r\n")
	}
	if err != nil {
		return outstr, err
	}
	return outstr, nil
}

func PutFile(client *sftp.Client, localpath string, remotepath string) error {
	// local
	fsrc, err := os.Open(localpath)
	if err != nil {
		return err
	}
	defer fsrc.Close()
	// remote
	fdst, err := client.Create(remotepath)
	if err != nil {
		return err
	}
	defer fdst.Close()

	_, err = fdst.ReadFrom(fsrc)
	return err
}

func WriteFile(client *sftp.Client, remotepath string, data []byte) error {
	r := bytes.NewReader(data)

	// remote
	fdst, err := client.Create(remotepath)
	if err != nil {
		return err
	}
	defer fdst.Close()

	_, err = fdst.ReadFrom(r)
	return err
}

func GetFile(client *sftp.Client, remotepath string, localpath string) error {
	// remote
	fsrc, err := client.Open(remotepath)
	if err != nil {
		return err
	}
	defer fsrc.Close()

	// local
	fdst, err := os.OpenFile(localpath, os.O_RDWR|os.O_CREATE, 0640)
	if err != nil {
		return err
	}
	defer fdst.Close()

	_, err = fsrc.WriteTo(fdst)
	return err
}
