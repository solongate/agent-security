/**
 * Wire types for the SolonGate v1 API, as consumed by the CLI.
 *
 * NOTE ON CASING: the API is inconsistent — policy list/version/audit responses
 * use snake_case (created_by, _version, tool_name), while settings/alerts/agents
 * baselines use camelCase (perMinute, windowSeconds). These types reflect what
 * the wire actually sends; the command/TUI layers read them as-is.
 */

// ── Policy core (apps/api/src/lib/security.ts) ──────────────────────────────

export type TrustLevel = 'UNTRUSTED' | 'VERIFIED' | 'TRUSTED';
export type Permission = 'READ' | 'WRITE' | 'EXECUTE' | 'NETWORK';
export type PolicyEffect = 'ALLOW' | 'DENY';
export type PolicyMode = 'denylist' | 'whitelist';

export interface Constraint {
  allowed?: string[];
  denied?: string[];
}

export interface PolicyRule {
  id: string;
  description: string;
  effect: PolicyEffect;
  priority: number;
  toolPattern: string;
  permission?: Permission | Permission[];
  minimumTrustLevel: TrustLevel;
  enabled: boolean;
  pathConstraints?: Constraint & { rootDirectory?: string; allowSymlinks?: boolean };
  commandConstraints?: Constraint;
  filenameConstraints?: Constraint;
  urlConstraints?: Constraint;
  argumentConstraints?: Record<string, unknown>;
}

export interface PolicySet {
  id: string;
  name: string;
  description?: string;
  version?: number;
  rules: PolicyRule[];
  mode?: PolicyMode;
  agents?: string[];
}

export interface PolicyListEntry {
  id: string;
  name: string;
  rules: PolicyRule[];
  mode: PolicyMode;
  version: number;
  hash: string;
  created_by: string;
  created_at: string;
}

export interface PolicyDetail extends PolicySet {
  _version: number;
  _hash: string;
  _created_at: string;
}

export interface PolicyVersion {
  version: number;
  hash: string;
  reason: string;
  created_by: string | null;
  created_at: string;
  rules_count: number;
}

export interface ActivePolicy {
  policy: PolicySet | null;
  version?: number;
  hash?: string;
  matched_by?: 'pinned' | 'policy-id' | 'agent' | 'wildcard';
  self_protection_enabled: boolean;
  security: {
    rateLimit: { perMinute: number; perHour: number; perDay: number } | null;
    dlpBlock: { patterns: string[]; custom: unknown[] } | null;
    dlpRedact: { patterns: string[]; custom: unknown[] } | null;
    ghost: { patterns: string[] } | null;
    localLogs: unknown;
  };
  hook_versions: { guard: number; audit: number; shield: number };
}

// ── Security layers / DLP (apps/api/src/lib/security-layers.ts) ─────────────

export type LayerMode = 'off' | 'detect' | 'block';

export interface SecurityLayers {
  rateLimit: { mode: LayerMode; perMinute: number; perHour: number; perDay: number };
  dlp: { mode: LayerMode; patterns: string[]; custom: { name: string; re: string }[] };
  ghost: { mode: 'off' | 'on'; patterns: string[] };
}

export interface RateLimitChange {
  ts: number;
  minute: number;
  hour: number;
  day: number;
}

// ── Stats ───────────────────────────────────────────────────────────────────

export interface Stats {
  total_calls: number;
  allowed: number;
  denied: number;
  active_policies: number;
  registered_tools: number;
  recent_activity: Array<{
    id: string;
    tool_name: string;
    decision: string;
    trust_level: string;
    evaluation_time_ms: number | null;
    created_at: string;
  }>;
}

export interface TimeseriesPoint {
  timestamp: string;
  total: number;
  allowed: number;
  denied: number;
  avg_eval_time_ms: number;
}

export interface Timeseries {
  timeseries: TimeseriesPoint[];
  period: string;
  granularity: 'hour' | 'day' | 'month';
}

export interface Drift {
  days: number;
  total_current: number;
  total_previous: number;
  rules: Array<{
    rule_id: string | null;
    reason: string | null;
    last_tool: string | null;
    current: number;
    previous: number;
    delta: number;
    delta_pct: number | null;
    is_new: boolean;
    spike: boolean;
  }>;
}

// ── Audit logs ───────────────────────────────────────────────────────────────

export interface AuditEntry {
  id: string;
  request_id: string;
  session_id: string | null;
  tool_name: string;
  server_name: string;
  permission: string;
  trust_level: string;
  decision: string;
  matched_rule_id: string | null;
  reason: string | null;
  evaluation_time_ms: number | null;
  arguments_summary: Record<string, unknown> | null;
  dlp_matches: string[];
  rate_limit_burst: boolean;
  agent_id: string | null;
  agent_name: string | null;
  created_at: string;
}

export interface AuditList {
  entries: AuditEntry[];
  total: number;
  limit: number;
  offset: number;
  rate_limit_per_minute: number;
}

// ── Agents ───────────────────────────────────────────────────────────────────

export interface LiveAgent {
  session_id: string;
  agent_id: string | null;
  agent_name: string | null;
  status: 'active' | 'idle' | 'deactivated';
  started_at: string;
  last_seen_at: string;
  total_calls: number;
  allowed_calls: number;
  denied_calls: number;
  dlp_events: number;
  rate_limit_events: number;
  pi_detections: number;
  tool_mix: { read: number; write: number; execute: number; network: number };
  character: string;
  trust_score: number;
  recent_anomalies: number;
}

export interface LiveAgents {
  agents: LiveAgent[];
  counts: { active: number; idle: number; deactivated: number };
}
