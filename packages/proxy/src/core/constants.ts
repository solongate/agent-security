// SPDX-License-Identifier: Apache-2.0

/** Default policy effect when no rule matches: DENY */
export const DEFAULT_POLICY_EFFECT = 'DENY' as const;

/** Maximum number of rules in a single PolicySet */
export const MAX_RULES_PER_POLICY_SET = 1000;

/** Maximum depth for nested argument validation */
export const MAX_ARGUMENT_DEPTH = 10;

/** Maximum size of tool arguments in bytes */
export const MAX_ARGUMENTS_SIZE_BYTES = 1_048_576; // 1MB

/** Maximum length of a tool name */
export const MAX_TOOL_NAME_LENGTH = 256;

/** Maximum length of a server name */
export const MAX_SERVER_NAME_LENGTH = 256;

/** Default rate limit per tool per minute */
export const DEFAULT_RATE_LIMIT_PER_MINUTE = 60;

/** Maximum rate limit per tool per minute */
export const MAX_RATE_LIMIT_PER_MINUTE = 10_000;

/** Security context timeout in milliseconds (5 minutes) */
export const SECURITY_CONTEXT_TIMEOUT_MS = 5 * 60 * 1000;

/** Policy evaluation timeout in milliseconds (100ms) */
export const POLICY_EVALUATION_TIMEOUT_MS = 100;

// --- Input Guard Constants ---

/** Default maximum length per string argument */
export const INPUT_GUARD_MAX_LENGTH = 4096;

/** Shannon entropy threshold for encoded payload detection */
export const INPUT_GUARD_ENTROPY_THRESHOLD = 4.5;

/** Minimum string length before entropy check applies */
export const INPUT_GUARD_MIN_ENTROPY_LENGTH = 32;

/** Maximum wildcards allowed per value */
export const INPUT_GUARD_MAX_WILDCARDS = 3;

// --- Token Constants ---

/** Default capability token TTL in seconds */
export const TOKEN_DEFAULT_TTL_SECONDS = 30;

/** Minimum secret key length for HMAC signing */
export const TOKEN_MIN_SECRET_LENGTH = 32;

/** Maximum token age before forced expiry (5 minutes) */
export const TOKEN_MAX_AGE_SECONDS = 300;

// --- Rate Limiter Constants ---

/** Default sliding window size in milliseconds (1 minute) */
export const RATE_LIMIT_WINDOW_MS = 60_000;

/** Maximum entries to keep per tool before cleanup */
export const RATE_LIMIT_MAX_ENTRIES = 10_000;

/** Warning messages for unsafe configurations. */
export const UNSAFE_CONFIGURATION_WARNINGS = {
  WILDCARD_ALLOW:
    'Wildcard ALLOW rules grant permission to ALL tools. This bypasses the default-deny model.',
  TRUSTED_LEVEL_EXTERNAL:
    'Setting trust level to TRUSTED for external requests bypasses all security checks.',
  WRITE_WITHOUT_READ:
    'Granting WRITE without READ is unusual and may indicate a misconfiguration.',
  EXECUTE_WITHOUT_REVIEW:
    'EXECUTE permission allows tools to perform arbitrary actions. Review carefully.',
  RATE_LIMIT_ZERO:
    'A rate limit of 0 means unlimited calls. This removes protection against runaway loops.',
  DISABLED_VALIDATION:
    'Disabling schema validation removes input sanitization protections.',
} as const;
