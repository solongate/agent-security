/**
 * A Set that automatically evicts entries after a configurable TTL.
 * Prevents unbounded memory growth in long-running processes.
 *
 * Uses a sweep-on-access strategy: expired entries are purged every
 * `sweepIntervalMs` when add() is called, keeping overhead minimal.
 */
export class ExpiringSet {
  private readonly entries = new Map<string, number>();
  private readonly ttlMs: number;
  private readonly sweepIntervalMs: number;
  private lastSweep = 0;

  constructor(ttlMs: number, sweepIntervalMs?: number) {
    this.ttlMs = ttlMs;
    this.sweepIntervalMs = sweepIntervalMs ?? Math.max(ttlMs, 60_000);
  }

  add(value: string): void {
    this.entries.set(value, Date.now());
    this.maybeSweep();
  }

  has(value: string): boolean {
    const ts = this.entries.get(value);
    if (ts === undefined) return false;
    if (Date.now() - ts > this.ttlMs) {
      this.entries.delete(value);
      return false;
    }
    return true;
  }

  get size(): number {
    this.maybeSweep();
    return this.entries.size;
  }

  private maybeSweep(): void {
    const now = Date.now();
    if (now - this.lastSweep < this.sweepIntervalMs) return;
    this.lastSweep = now;

    const cutoff = now - this.ttlMs;
    for (const [key, ts] of this.entries) {
      if (ts < cutoff) this.entries.delete(key);
    }
  }
}
