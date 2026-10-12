// SPDX-License-Identifier: Apache-2.0

package sandbox

// BoxPlan is what the closed box needs. It is not Plan: Plan describes paths on
// the host to allow or deny, and nothing in a box is on the host.
type BoxPlan struct {
	// Workspace is the project, bound in read-write. It is the only writable
	// thing in the box that survives the box exiting.
	Workspace string

	// Runtime are host directories bound in READ-ONLY at the same path,
	// because the agent needs them to execute. See DefaultBoxRuntime.
	Runtime []string

	// AgentTree is the agent's own install directory, bound read-only at
	// /opt/agent — NOT at its host path. Binding it where it lives would mean
	// /home/<user>/.local existed inside the box, which is the one thing this
	// mode is for.
	AgentTree string

	// AgentExec is the command to run inside, already rewritten to its path in
	// the box.
	AgentExec []string

	// Network is whether the box keeps the network. It is the one hole that is
	// not a filesystem hole, and it is per-box because neither answer is right
	// in general: off is airtight and cannot reach the model that drives the
	// agent, on lets the agent work and leaves what leaves to the DLP and
	// egress layers, which read content a mount namespace cannot see.
	Network bool
}
