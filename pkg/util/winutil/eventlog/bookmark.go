// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build !windows
// +build !windows

package eventlog

import (
	"fmt"
	"os"

	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"
	"golang.org/x/sys/windows"
)

func OpenBookmarkFromPath(bookmarkPath string) (api.EventBookmarkHandle, error) {
	// Read bookmark from file
	bookmarkXml, err := os.ReadFile(bookmarkPath)
	if err != nil {
		return api.EventBookmarkHandle(0), err
	}

	// Load bookmark XML
	bookmarkHandle, err := EvtCreateBookmark(string(bookmarkXml))
	if err != nil {
		return api.EventBookmarkHandle(0), err
	}

	return bookmarkHandle, nil
}

func RenderBookmark(bookmarkHandle api.EventBookmarkHandle) (string, error) {
	// Render bookmark
	buf, err := EvtRenderText(bookmarkHandle, EvtRenderBookmark)
	if err != nil {
		return "", err
	} else if buf == nil || len(buf) == 0 {
		return "", fmt.Errorf("Bookmark is empty")
	}

	// Convert to string
	return windows.UTF16ToString(buf), nil
}

func WriteBookmarkToPath(bookmarkHandle api.EventBookmarkHandle, path string) (err error) {
	// Render bookmark to a string
	bookmarkXml, err := RenderBookmark(bookmarkHandle)
	if err != nil {
		return err
	}

	// Open the destination file, create if needed, overwrite if exists
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		err1 := f.Close()
		if err == nil {
			// write failure takes precedence
			err = err1
		}
	}()

	// Write bookmark XML to file
	_, err = f.WriteString(bookmarkXml)
	if err != nil {
		return err
	}

	return nil
}
