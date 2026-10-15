// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

// Package vocab holds the permission vocabulary the local store speaks.
//
// WHAT WAS HERE AND WHY IT IS NOT. This package carried a full security model
// written for a product with a server in it: a three-level TrustLevel state
// machine with an escalation guard, an HS256 CapabilityToken with per-tool and
// per-path scopes, a typed error taxonomy, MCP tool and result shapes, an
// execution-request envelope, and a second PolicyRule/PolicySet declaration
// alongside the one in core/client. Around 570 lines of it. Nothing outside this
// package ever referenced any of it, the only symbol another package used was
// the Permission type below, for a conversion in core/client/types.go.
//
// None of it was dead by accident. It described the thing the guard was going to
// be before the service was removed, and reading it gave the impression of
// capabilities that do not exist: trust_level is pinned to "TRUSTED" in the
// policy input (see packages/policy), so the escalation machine had nothing to
// guard, and no code ever signed or verified a capability token. A reader
// looking for how trust is granted found a complete answer that was never
// wired to anything.
//
// So it is gone rather than kept for later. The commit it was deleted in is the
// record of what it said, which is a better place for a design that is not
// running than a package every build compiles.
package vocab

// Permission categories are ALWAYS evaluated independently. Holding READ does
// not imply WRITE or EXECUTE.
//
// NOT THE ENFORCING CLASSIFIER. What a policy rule matches on is
// `input.permission`, produced by shared.GuessPermission and the guard's own
// copy; this type is the vocabulary those strings come from, and core/client
// converts into it when it reads a rule off disk. The classifier that used to
// live here was a second, subtly different implementation of that decision,
// it called a Codex `apply_patch` a READ, and a guess about a permission that
// disagrees with the one being enforced is worse than no guess.
type Permission string

const (
	PermRead    Permission = "READ"
	PermWrite   Permission = "WRITE"
	PermExecute Permission = "EXECUTE"
	PermNetwork Permission = "NETWORK"
)