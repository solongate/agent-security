import type { PolicySet } from './core/index.js';
import { readFileSync, watch, existsSync } from 'node:fs';


const log = (...args: unknown[]) => process.stderr.write(`[SolonGate Sync] ${args.map(String).join(' ')}\n`);

export interface PolicySyncOptions {
  /** Absolute path to the policy file, or null when there is none to watch. */
  localPath: string | null;
  /** Called when the file changes and the new policy differs. */
  onPolicyUpdate: (policy: PolicySet) => void;
  /** The policy already loaded, to compare a file change against. */
  initialPolicy: PolicySet;
}

/**
 * Watches the policy file and reloads the policy when it changes. Kept in step with
 * internal/proxy/sync.go.
 *
 *   the file changes → the running proxy enforces the new rules
 *
 * It WAS bidirectional — the file pushed up, the service's copy written down, a
 * version number deciding which was newer — and most of the care in it went on the
 * loop that creates: a write caused by a poll must not read as a person's edit and
 * get pushed straight back. One direction remains, and it is the one that was always
 * doing the work. The file is the source of truth, and NOTHING HERE WRITES TO IT.
 */
export class PolicySyncManager {
  private localPath: string | null;
  private onPolicyUpdate: (policy: PolicySet) => void;

  private currentPolicy: PolicySet;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private watcher: ReturnType<typeof watch> | null = null;

  constructor(opts: PolicySyncOptions) {
    this.localPath = opts.localPath;
    this.onPolicyUpdate = opts.onPolicyUpdate;
    this.currentPolicy = opts.initialPolicy;
  }

  /**
   * Start watching the policy file.
   *
   * It used to poll a service for a newer policy and push the local file up to one,
   * which is where "sync" comes from. What is left is the half about this machine,
   * and it matters more than it did: the file is the only source, so somebody
   * editing it expects the proxy to follow without a restart.
   */
  start(): void {
    if (this.localPath && existsSync(this.localPath)) {
      this.startFileWatcher();
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
   * Reload the policy from the file.
   *
   * Two things used to make this WRITE to the file, and both were about the far end
   * of a sync:
   *
   * The version bump — an edit that did not raise the version got one raised for it
   * and the file rewritten, to stay ahead of a service that was also writing.
   * Nothing has to accept the edit now; the rules are in force the moment they parse.
   * Rewriting a file somebody is editing, to change a field they did not touch, is a
   * bad trade for a number only a status line reads.
   *
   * The self-write guard — a change event caused by our own write had to be ignored
   * for a second, or the poll pushed back up the policy it had just pulled. With no
   * write of our own there is no ambiguity left, and an edit is picked up a second
   * sooner.
   */
  private async onFileChange(filePath: string): Promise<void> {
    try {
      if (!existsSync(filePath)) {
        log('Policy file deleted — keeping current policy');
        return;
      }

      const content = readFileSync(filePath, 'utf-8');
      const newPolicy = JSON.parse(content) as PolicySet;

      // RULES, not the version, decide whether this is a change: somebody who edits a
      // rule and leaves the version alone has still changed the policy, and that is
      // the normal way to edit a file by hand.
      if (this.policiesEqual(newPolicy, this.currentPolicy)) return;

      log(`File changed: ${newPolicy.name} v${newPolicy.version}`);
      this.currentPolicy = newPolicy;
      this.onPolicyUpdate(newPolicy);
    } catch (err) {
      log(`File read error: ${err instanceof Error ? err.message : String(err)}`);
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
