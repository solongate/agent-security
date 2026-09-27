
CREATE TABLE `agent_baselines` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`agent_id` text NOT NULL,
	`tool_distribution` text DEFAULT '{}',
	`permission_mix` text DEFAULT '{}',
	`known_paths` text DEFAULT '[]',
	`known_domains` text DEFAULT '[]',
	`known_tools` text DEFAULT '[]',
	`avg_calls_per_hour` real DEFAULT 0,
	`deny_rate` real DEFAULT 0,
	`sample_size` integer DEFAULT 0 NOT NULL,
	`character` text,
	`trust_score` real DEFAULT 50,
	`computed_at` integer NOT NULL,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `agent_baselines_project_agent_idx` ON `agent_baselines` (`project_id`,`agent_id`);--> statement-breakpoint
CREATE TABLE `agent_group_members` (
	`id` text PRIMARY KEY NOT NULL,
	`group_id` text NOT NULL,
	`agent_id` text NOT NULL,
	`project_id` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`group_id`) REFERENCES `agent_groups`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `agent_group_members_group_id_idx` ON `agent_group_members` (`group_id`);--> statement-breakpoint
CREATE INDEX `agent_group_members_agent_id_idx` ON `agent_group_members` (`agent_id`);--> statement-breakpoint
CREATE INDEX `agent_group_members_project_id_idx` ON `agent_group_members` (`project_id`);--> statement-breakpoint
CREATE TABLE `agent_groups` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`name` text NOT NULL,
	`description` text DEFAULT '',
	`color` text DEFAULT '#6366f1',
	`policy_rules` text DEFAULT '[]',
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `agent_groups_project_id_idx` ON `agent_groups` (`project_id`);--> statement-breakpoint
CREATE TABLE `agent_relationships` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`source_agent_id` text NOT NULL,
	`target_agent_id` text NOT NULL,
	`relationship_type` text DEFAULT 'peer' NOT NULL,
	`trust_level` text DEFAULT 'VERIFIED',
	`allowed_tools` text DEFAULT '[]',
	`denied_tools` text DEFAULT '[]',
	`allowed_permissions` text DEFAULT '[]',
	`max_delegation_depth` integer DEFAULT 1,
	`enabled` integer DEFAULT true NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `agent_relationships_project_id_idx` ON `agent_relationships` (`project_id`);--> statement-breakpoint
CREATE INDEX `agent_relationships_source_idx` ON `agent_relationships` (`project_id`,`source_agent_id`);--> statement-breakpoint
CREATE INDEX `agent_relationships_target_idx` ON `agent_relationships` (`project_id`,`target_agent_id`);--> statement-breakpoint
CREATE TABLE `agents` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`agent_id` text NOT NULL,
	`agent_name` text,
	`first_seen_at` integer NOT NULL,
	`last_seen_at` integer NOT NULL,
	`total_calls` integer DEFAULT 0 NOT NULL,
	`allowed_calls` integer DEFAULT 0 NOT NULL,
	`denied_calls` integer DEFAULT 0 NOT NULL,
	`pi_detections` integer DEFAULT 0 NOT NULL,
	`parent_agent_id` text,
	`api_key_id` text,
	`api_key_name` text,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `agents_project_id_idx` ON `agents` (`project_id`);--> statement-breakpoint
CREATE INDEX `agents_project_agent_id_idx` ON `agents` (`project_id`,`agent_id`);--> statement-breakpoint
CREATE INDEX `agents_api_key_id_idx` ON `agents` (`api_key_id`);--> statement-breakpoint
CREATE TABLE `anomaly_events` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`agent_id` text NOT NULL,
	`session_id` text,
	`audit_log_id` text,
	`kind` text NOT NULL,
	`severity` text DEFAULT 'low' NOT NULL,
	`score` real DEFAULT 0,
	`description` text,
	`detail` text,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `anomaly_events_project_created_idx` ON `anomaly_events` (`project_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `anomaly_events_project_agent_idx` ON `anomaly_events` (`project_id`,`agent_id`);--> statement-breakpoint
CREATE TABLE `api_keys` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`key_prefix` text NOT NULL,
	`key_hash` text NOT NULL,
	`name` text NOT NULL,
	`is_live` integer DEFAULT false NOT NULL,
	`user_id` text,
	`last_used_at` integer,
	`revoked_at` integer,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `api_keys_key_prefix_idx` ON `api_keys` (`key_prefix`);--> statement-breakpoint
CREATE INDEX `api_keys_project_id_idx` ON `api_keys` (`project_id`);--> statement-breakpoint
CREATE INDEX `api_keys_project_name_idx` ON `api_keys` (`project_id`,`name`);--> statement-breakpoint
CREATE TABLE `conversation_turns` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`api_key_id` text,
	`user_id` text,
	`session_id` text NOT NULL,
	`agent_id` text,
	`agent_name` text,
	`source` text,
	`role` text NOT NULL,
	`body` text NOT NULL,
	`redacted` integer DEFAULT 0 NOT NULL,
	`truncated` integer DEFAULT 0 NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `conversation_turns_project_user_created_idx` ON `conversation_turns` (`project_id`,`user_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `conversation_turns_session_idx` ON `conversation_turns` (`session_id`);--> statement-breakpoint
CREATE TABLE `audit_logs` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`request_id` text NOT NULL,
	`session_id` text,
	`tool_name` text NOT NULL,
	`server_name` text,
	`permission` text NOT NULL,
	`trust_level` text NOT NULL,
	`decision` text NOT NULL,
	`matched_rule_id` text,
	`reason` text,
	`evaluation_time_ms` real,
	`arguments_hash` text,
	`arguments_summary` text,
	`pi_detected` integer,
	`pi_trust_score` real,
	`pi_blocked` integer,
	`pi_categories` text,
	`pi_stage_scores` text,
	`agent_id` text,
	`agent_name` text,
	`sub_agent_id` text,
	`sub_agent_name` text,
	`api_key_id` text,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `audit_logs_project_id_created_at_idx` ON `audit_logs` (`project_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `audit_logs_agent_id_idx` ON `audit_logs` (`agent_id`);--> statement-breakpoint
CREATE INDEX `audit_logs_session_id_idx` ON `audit_logs` (`project_id`,`session_id`);--> statement-breakpoint
CREATE TABLE `delegation_chains` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`chain` text NOT NULL,
	`origin_agent_id` text NOT NULL,
	`terminal_agent_id` text NOT NULL,
	`effective_tools` text DEFAULT '[]',
	`effective_permissions` text DEFAULT '[]',
	`status` text DEFAULT 'active' NOT NULL,
	`expires_at` integer,
	`created_at` integer NOT NULL,
	`revoked_at` integer,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `delegation_chains_project_id_idx` ON `delegation_chains` (`project_id`);--> statement-breakpoint
CREATE INDEX `delegation_chains_origin_idx` ON `delegation_chains` (`origin_agent_id`);--> statement-breakpoint
CREATE INDEX `delegation_chains_terminal_idx` ON `delegation_chains` (`terminal_agent_id`);--> statement-breakpoint
CREATE TABLE `mcp_servers` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`name` text NOT NULL,
	`url` text NOT NULL,
	`status` text DEFAULT 'inactive' NOT NULL,
	`command` text,
	`args` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `mcp_servers_project_id_idx` ON `mcp_servers` (`project_id`);--> statement-breakpoint
CREATE TABLE `org_members` (
	`id` text PRIMARY KEY NOT NULL,
	`org_id` text NOT NULL,
	`user_id` text NOT NULL,
	`role` text DEFAULT 'member' NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`org_id`) REFERENCES `organizations`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `org_members_org_user_unique` ON `org_members` (`org_id`,`user_id`);--> statement-breakpoint
CREATE INDEX `org_members_org_id_idx` ON `org_members` (`org_id`);--> statement-breakpoint
CREATE INDEX `org_members_user_id_idx` ON `org_members` (`user_id`);--> statement-breakpoint
CREATE TABLE `organizations` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`slug` text NOT NULL,
	`owner_id` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`owner_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `organizations_slug_unique` ON `organizations` (`slug`);--> statement-breakpoint
CREATE INDEX `organizations_owner_id_idx` ON `organizations` (`owner_id`);--> statement-breakpoint
CREATE TABLE `policy_versions` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`version` integer NOT NULL,
	`policy_data` text NOT NULL,
	`hash` text NOT NULL,
	`reason` text,
	`created_by` text,
	`rego_source` text,
	`wasm_bundle` text,
	`variant_artifacts` text,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `policy_versions_project_id_version_idx` ON `policy_versions` (`project_id`,`version`);--> statement-breakpoint
CREATE TABLE `projects` (
	`id` text PRIMARY KEY NOT NULL,
	`owner_id` text NOT NULL,
	`org_id` text,
	`name` text NOT NULL,
	`slug` text NOT NULL,
	`description` text DEFAULT '',
	`token_secret` text NOT NULL,
	`pi_enabled` integer DEFAULT true,
	`pi_threshold` real DEFAULT 0.5,
	`pi_mode` text DEFAULT 'block',
	`pi_whitelist` text,
	`pi_tool_config` text,
	`pi_custom_patterns` text,
	`pi_webhook_url` text,
	`ai_judge_enabled` integer DEFAULT false,
	`ai_judge_model` text DEFAULT 'llama-3.1-8b-instant',
	`ai_judge_endpoint` text DEFAULT 'https://api.groq.com/openai',
	`ai_judge_timeout_ms` integer DEFAULT 5000,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`owner_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`org_id`) REFERENCES `organizations`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE UNIQUE INDEX `projects_slug_unique` ON `projects` (`slug`);--> statement-breakpoint
CREATE INDEX `projects_owner_id_idx` ON `projects` (`owner_id`);--> statement-breakpoint
CREATE INDEX `projects_org_id_idx` ON `projects` (`org_id`);--> statement-breakpoint
CREATE TABLE `sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`agent_id` text,
	`agent_name` text,
	`api_key_id` text,
	`started_at` integer NOT NULL,
	`last_seen_at` integer NOT NULL,
	`total_calls` integer DEFAULT 0 NOT NULL,
	`allowed_calls` integer DEFAULT 0 NOT NULL,
	`denied_calls` integer DEFAULT 0 NOT NULL,
	`dlp_events` integer DEFAULT 0 NOT NULL,
	`rate_limit_events` integer DEFAULT 0 NOT NULL,
	`pi_detections` integer DEFAULT 0 NOT NULL,
	`read_calls` integer DEFAULT 0 NOT NULL,
	`write_calls` integer DEFAULT 0 NOT NULL,
	`execute_calls` integer DEFAULT 0 NOT NULL,
	`network_calls` integer DEFAULT 0 NOT NULL,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `sessions_project_id_last_seen_idx` ON `sessions` (`project_id`,`last_seen_at`);--> statement-breakpoint
CREATE INDEX `sessions_project_agent_idx` ON `sessions` (`project_id`,`agent_id`);--> statement-breakpoint
CREATE TABLE `solon_usage` (
	`user_id` text PRIMARY KEY NOT NULL,
	`chats_used` integer DEFAULT 0 NOT NULL,
	`policies_used` integer DEFAULT 0 NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `system_settings` (
	`key` text PRIMARY KEY NOT NULL,
	`value` text NOT NULL,
	`description` text,
	`updated_by` text,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `tools` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`name` text NOT NULL,
	`description` text DEFAULT '',
	`input_schema` text,
	`permissions` text DEFAULT '["READ"]',
	`enabled` integer DEFAULT true NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `tools_project_id_idx` ON `tools` (`project_id`);--> statement-breakpoint
CREATE TABLE `used_nonces` (
	`nonce` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`used_at` integer NOT NULL,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `used_nonces_project_id_idx` ON `used_nonces` (`project_id`);--> statement-breakpoint
CREATE TABLE `users` (
	`id` text PRIMARY KEY NOT NULL,
	`email` text NOT NULL,
	`name` text,
	`password_hash` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_email_unique` ON `users` (`email`);