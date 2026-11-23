// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

// tokens counts the panels handed out across the live, audit, and panels
// packages, so one token identifies one panel instance process-wide.
var tokens int

// NextToken returns a fresh token, one higher than the last handed out. It
// replaces the identical per-package counters live, audit, and panels each
// kept for the same job.
func NextToken() int { tokens++; return tokens }
