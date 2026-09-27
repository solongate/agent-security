package policycompile

import "github.com/codeyevsky/solongate/sgpolicy"

// The Rego compiler is packages/sgpolicy's, imported rather than transcribed.
//
// It used to be a copy kept honest by a test that read guard-go's file and
// compared it byte for byte. That worked, and it was still a copy: when the
// engine moved into its own module the test stopped finding the file it read
// and SKIPPED, which is the failure mode a drift check must not have. A skipped
// guard against divergence is worse than none, because it reports success.
//
// What divergence would have cost is worth stating: this service compiles a
// policy for the WASM bundle it serves, and packages/guard-go compiles the same
// policy on the machine. If the two disagree, a laptop evaluating locally and
// one evaluating the served bundle enforce different rules, and nothing
// anywhere reports a problem. Now there is one compiler and the question cannot
// arise.
type (
	PolicyRule        = sgpolicy.PolicyRule
	ListConstraints   = sgpolicy.ListConstraints
	PathConstraintSet = sgpolicy.PathConstraintSet
)

var (
	ConvertRulesToRego = sgpolicy.ConvertRulesToRego
	ParsePolicyRules   = sgpolicy.ParsePolicyRules
)
