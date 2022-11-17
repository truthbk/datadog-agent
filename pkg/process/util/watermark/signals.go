// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package watermark

// SignalType represents a type of a watermark signal
type SignalType int32

const (
	ItemCount80Full SignalType = iota
	ItemCount90Full
	ItemCount100Full
)

// String returns the string representation of a SignalType
func (e SignalType) String() string {
	switch e {
	case ItemCount80Full:
		return "item_count_80_full"
	case ItemCount90Full:
		return "item_count_90_full"
	case ItemCount100Full:
		return "item_count_100_full"
	}
	return "unknown"
}

type Signal struct {
	SignalType SignalType
}
