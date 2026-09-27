import type { PolicySet } from './core/index.js';
import { readFileSync, writeFileSync, watch, existsSync } from 'node:fs';
import { fetchCloudPolicy } from './config.js';

const log = (...args: unknown[]) => process.stderr.write(`[SolonGate Sync] ${args.map(String).join(' ')}\n`);

export interface PolicySyncOptions {
  /** Absolute path to local policy JSON file (null if cloud-only) */
  localPath: string | null;
  /** SolonGate API key */
  apiKey: string;
  /** SolonGate API URL */
  apiUrl: string;
  /** Polling interval in ms (default: 60000) */
  pollIntervalMs?: number;
  /** Called when policy is updated from either source */
  onPolicyUpdate: (policy: PolicySet) => void;
  /** Initial policy (the currently loaded one) */
  initialPolicy: PolicySet;
  /** Cloud policy ID — determines which cloud policy to push/pull */
  policyId?: string;
}

/**
 * Bidirectional policy sync between local JSON file and SolonGate Cloud.
 *
 * - Watches local file for changes → pushes to cloud API (using policyId from CLI)
 * - Polls cloud API for changes → writes to local file
 * - Version number determines which is newer (higher wins)
 * - Loop prevention: skipNextWatch flag when writing to file
 */
export class PolicySyncManager {
  private localPath: string | null;
  private apiKey: string;
  private apiUrl: string;
  private pollIntervalMs: number;
  private onPolicyUpdate: (policy: PolicySet) => void;

  private currentPolicy: PolicySet;
  private localVersion: number;
  private cloudVersion: number;
  private lastWriteTime = 0;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private watcher: ReturnType<typeof watch> | null = null;
  private isLiveKey: boolean;
  /** The cloud policy ID from --policy-id flag. This is the ONLY source of truth for which cloud policy to use. */
  private policyId?: string;

  constructor(opts: PolicySyncOptions) {
    this.localPath = opts.localPath;
    this.apiKey = opts.apiKey;
    this.apiUrl = opts.apiUrl;
    this.policyId = opts.policyId;
    this.pollIntervalMs = opts.pollIntervalMs ?? 60_000;
    this.onPolicyUpdate = opts.onPolicyUpdate;
    this.currentPolicy = opts.initialPolicy;
    this.localVersion = opts.initialPolicy.version ?? 0;
    this.cloudVersion = 0;
    this.isLiveKey = opts.apiKey.startsWith('sg_live_');
  }

  /**
   * Start watching local file and polling cloud.
   */
  start(): void {
    // Start file watcher (if local file exists)
    if (this.localPath && existsSync(this.localPath)) {
      this.startFileWatcher();
    }

    // Start cloud polling (if live key)
    if (this.isLiveKey) {
      // Initial push of local policy to cloud
      this.pushToCloud(this.currentPolicy).catch(() => {});
      this.startPolling();
    }
  }

  /**
   * Stop all watchers and timers.
   */
  stop(): void {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
  }

  /**
   * Watch local file for changes (debounced).
   */
  private startFileWatcher(): void {
    if (!this.localPath) return;
    const filePath = this.localPath;

    try {
      this.watcher = watch(filePath, () => {
        // Debounce: editors often write multiple times
        if (this.debounceTimer) clearTimeout(this.debounceTimer);
        this.debounceTimer = setTimeout(() => this.onFileChange(filePath), 300);
      });
      log(`Watching ${filePath} for changes`);
    } catch (err) {
      log(`File watch failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Handle local file change event.
   */
  private async onFileChange(filePath: string): Promise<void> {
    // Skip if we recently wrote this file ourselves (timestamp-based debounce)
    if (Date.now() - this.lastWriteTime < 1000) {
      return;
    }

    try {
      if (!existsSync(filePath)) {
        log('Policy file deleted — keeping current policy');
        return;
      }

      const content = readFileSync(filePath, 'utf-8');
      const newPolicy = JSON.parse(content) as PolicySet;

      // Auto-increment version if user didn't change it
      if (newPolicy.version <= this.localVersion) {
        (newPolicy as { version: number }).version = Math.max(this.localVersion, this.cloudVersion) + 1;
        // Write back the auto-incremented version
        this.writeToFile(newPolicy);
      }

      // Check if actually different
      if (this.policiesEqual(newPolicy, this.currentPolicy)) return;

      log(`File changed: ${newPolicy.name} v${newPolicy.version}`);
      this.localVersion = newPolicy.version;
      this.currentPolicy = newPolicy;
      this.onPolicyUpdate(newPolicy);

      // Push to cloud if live key
      if (this.isLiveKey) {
        try {
          const result = await this.pushToCloud(newPolicy);
          this.cloudVersion = result.version;
          log(`Pushed to cloud: v${result.version}`);
        } catch (err) {
          log(`Cloud push failed: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    } catch (err) {
      log(`File read error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Poll cloud for policy changes.
   */
  private startPolling(): void {
    this.pollTimer = setInterval(() => this.onPollTick(), this.pollIntervalMs);
  }

  /**
   * Handle poll tick — fetch cloud policy and compare.
   */
  private async onPollTick(): Promise<void> {
    try {
      const cloudPolicy = await fetchCloudPolicy(this.apiKey, this.apiUrl, this.policyId);
      const cloudVer = cloudPolicy.version ?? 0;

      // Only update if cloud is newer
      if (cloudVer <= this.localVersion && this.policiesEqual(cloudPolicy, this.currentPolicy)) {
        return;
      }

      // Cloud is newer or different at same version (cloud wins on tie)
      if (cloudVer > this.localVersion || !this.policiesEqual(cloudPolicy, this.currentPolicy)) {
        log(`Cloud update: ${cloudPolicy.name} v${cloudVer} (was v${this.localVersion})`);
        this.cloudVersion = cloudVer;
        this.localVersion = cloudVer;
        this.currentPolicy = cloudPolicy;
        this.onPolicyUpdate(cloudPolicy);

        // Write to local file if we have one
        if (this.localPath) {
          this.writeToFile(cloudPolicy);
          log(`Updated local file: ${this.localPath}`);
        }
      }
    } catch {
      // Silent — don't interrupt proxy operation
    }
  }

  /**
   * Push policy to cloud API.
   * Uses this.policyId (from --policy-id CLI flag) as the cloud policy ID.
   * Falls back to policy.id from local file only if --policy-id was not set.
   */
  private async pushToCloud(policy: PolicySet): Promise<{ version: number }> {
    // CLI --policy-id takes priority over local file's id field
    const cloudId = this.policyId || policy.id || 'default';

    const payload = JSON.stringify({
      id: cloudId,
      name: policy.name || 'Default Policy',
      description: policy.description || 'Synced from proxy',
      version: policy.version || 1,
      rules: policy.rules,
    });

    // Try PUT first (update existing), fall back to POST (create) on 404
    const putRes = await fetch(`${this.apiUrl}/api/v1/policies/${cloudId}`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: payload,
    });

    if (putRes.ok) {
      const data = await putRes.json() as Record<string, unknown>;
      return { version: Number(data._version ?? policy.version) };
    }

    // 404 means policy doesn't exist yet — create with POST
    if (putRes.status === 404) {
      const postRes = await fetch(`${this.apiUrl}/api/v1/policies`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: payload,
      });

      if (!postRes.ok) {
        const body = await postRes.text().catch(() => '');
        throw new Error(`Push failed (${postRes.status}): ${body}`);
      }

      const data = await postRes.json() as Record<string, unknown>;
      return { version: Number(data._version ?? policy.version) };
    }

    const body = await putRes.text().catch(() => '');
    throw new Error(`Push failed (${putRes.status}): ${body}`);
  }

  /**
   * Write policy to local file (with loop prevention).
   * Does NOT write the 'id' field — cloud ID is managed by --policy-id flag.
   */
  private writeToFile(policy: PolicySet): void {
    if (!this.localPath) return;

    this.lastWriteTime = Date.now();
    try {
      // Write policy without 'id' field — id is managed by --policy-id flag
      const { id: _id, ...rest } = policy as PolicySet & { id?: string };
      const json = JSON.stringify(rest, null, 2) + '\n';
      writeFileSync(this.localPath, json, 'utf-8');
    } catch (err) {
      log(`File write error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Compare two policies by rules content (ignoring timestamps and id).
   */
  private policiesEqual(a: PolicySet, b: PolicySet): boolean {
    if (a.name !== b.name || a.rules.length !== b.rules.length) return false;
    // Always deep compare rules to ensure correctness
    return JSON.stringify(a.rules) === JSON.stringify(b.rules);
  }
}
