// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package sandbox

type BoxPlan struct {
	Workspace string

	Runtime []string

	AgentTree string

	AgentExec []string

	Network bool
}