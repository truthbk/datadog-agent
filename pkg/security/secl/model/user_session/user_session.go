// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package user_session

var (
	// UserSessionTypes are the supported user session types
	UserSessionTypes = map[string]UserSessionType{
		"unknown": 0,
		"k8s":     1,
	}

	// UserSessionTypeStrings is used to
	UserSessionTypeStrings = map[UserSessionType]string{}
)

// UserSessionType is used to identify the User Session type
type UserSessionType uint8

func (ust UserSessionType) String() string {
	return UserSessionTypeStrings[ust]
}

// InitUserSessionTypes initializes internal structures for parsing UserSessionType values
func InitUserSessionTypes() {
	for k, v := range UserSessionTypes {
		UserSessionTypeStrings[v] = k
	}
}
