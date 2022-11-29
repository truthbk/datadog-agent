// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.
package stress

import (
	"time"

	"github.com/DataDog/datadog-agent/pkg/collector/check"
	core "github.com/DataDog/datadog-agent/pkg/collector/corechecks"
)

const spinCheckName = "spin"
const spinTime = time.Millisecond * 500

// Use CheckBase fields only
type SpinCheck struct {
	core.CheckBase
}

// Run executes the check
func (c *SpinCheck) Run() error {
	sender, err := c.GetSender()
	if err != nil {
		return err
	}

	start := time.Now()
	for {
		if time.Since(start) >= spinTime {
			break
		}
	}

	sender.Count("stress.spin.executed", 1, "", nil)
	return nil
}

func loadFactory() check.Check {
	return &SpinCheck{
		CheckBase: core.NewCheckBase(spinCheckName),
	}
}

func init() {
	core.RegisterCheck(spinCheckName, loadFactory)
}
