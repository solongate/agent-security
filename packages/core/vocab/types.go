// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package vocab

type Permission string

const (
	PermRead    Permission = "READ"
	PermWrite   Permission = "WRITE"
	PermExecute Permission = "EXECUTE"
	PermNetwork Permission = "NETWORK"
)