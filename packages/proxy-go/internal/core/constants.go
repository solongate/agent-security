// Package core is the security vocabulary the rest of the CLI is written in:
// trust levels, permissions, the policy shapes, the errors, and the input
// guard.
//
// It is a port of packages/proxy/src/core. Nothing here reaches the network or
// the filesystem, and nothing here decides anything on its own — the enforcing
// decision path is packages/guard-go, and this package exists so the CLI can
// talk about the same things in the same words.
package core

// DefaultPolicyEffect is what happens when no rule matches.
const DefaultPolicyEffect = EffectDeny

const (
	MaxRulesPerPolicySet = 1000
	MaxArgumentDepth     = 10
	// 1 MB.
	MaxArgumentsSizeBytes = 1_048_576
	MaxToolNameLength     = 256
	MaxServerNameLength   = 256

	DefaultRateLimitPerMinute = 60
	MaxRateLimitPerMinute     = 10_000

	SecurityContextTimeoutMs = 5 * 60 * 1000
	PolicyEvaluationTimeout  = 100 // ms
)

// Input guard thresholds.
const (
	InputGuardMaxLength = 4096
	// Shannon bits per character. Base64-encoded data sits around 6.0.
	InputGuardEntropyThreshold = 4.5
	// Below this length entropy says nothing useful, so the check is skipped.
	InputGuardMinEntropyLength = 32
	InputGuardMaxWildcards     = 3
)

// Capability token constants. The token itself is not issued by the CLI; these
// are here because the shapes travel with the core types.
const (
	TokenDefaultTTLSeconds = 30
	TokenMinSecretLength   = 32
	TokenMaxAgeSeconds     = 300
)

// Rate limiter constants.
const (
	RateLimitWindowMs   = 60_000
	RateLimitMaxEntries = 10_000
)

// UnsafeConfigurationWarnings are the exact strings shown when a configuration
// weakens the model rather than breaking it. They are phrased as consequences,
// not as rule names, because they are read by someone deciding whether to keep
// the setting.
var UnsafeConfigurationWarnings = map[string]string{
	"WILDCARD_ALLOW":         "Wildcard ALLOW rules grant permission to ALL tools. This bypasses the default-deny model.",
	"TRUSTED_LEVEL_EXTERNAL": "Setting trust level to TRUSTED for external requests bypasses all security checks.",
	"WRITE_WITHOUT_READ":     "Granting WRITE without READ is unusual and may indicate a misconfiguration.",
	"EXECUTE_WITHOUT_REVIEW": "EXECUTE permission allows tools to perform arbitrary actions. Review carefully.",
	"RATE_LIMIT_ZERO":        "A rate limit of 0 means unlimited calls. This removes protection against runaway loops.",
	"DISABLED_VALIDATION":    "Disabling schema validation removes input sanitization protections.",
}
