
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