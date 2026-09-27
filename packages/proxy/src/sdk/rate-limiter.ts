import { RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX_ENTRIES } from '../core/index.js';

/**
 * Result of a rate limit check.
 */
export interface RateLimitResult {
  readonly allowed: boolean;
  readonly remaining: number;
  readonly resetAt: number;
}

/**
 * Fixed-size circular buffer for timestamps.
 * O(1) push, O(log n) count-in-window via binary search.
 * Automatically overwrites oldest entries when full.
 */
class CircularTimestampBuffer {
  private readonly buf: Float64Array;
  private head = 0; // next write position
  private size = 0; // current number of entries

  constructor(capacity: number) {
    this.buf = new Float64Array(capacity);
  }

  push(timestamp: number): void {
    this.buf[this.head] = timestamp;
    this.head = (this.head + 1) % this.buf.length;
    if (this.size < this.buf.length) this.size++;
  }

  /**
   * Count entries with timestamp > windowStart.
   * Since timestamps are monotonically increasing in the ring,
   * we use binary search on the logical sorted order.
   */
  countAfter(windowStart: number): number {
    if (this.size === 0) return 0;

    // All entries are within window
    const oldest = this.at(0);
    if (oldest > windowStart) return this.size;

    // Binary search for the first entry > windowStart
    let lo = 0;
    let hi = this.size;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (this.at(mid) > windowStart) {
        hi = mid;
      } else {
        lo = mid + 1;
      }
    }
    return this.size - lo;
  }

  /** Get the oldest entry timestamp (for resetAt calculation) */
  oldestInWindow(windowStart: number): number | null {
    if (this.size === 0) return null;

    // Binary search for first entry > windowStart
    let lo = 0;
    let hi = this.size;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (this.at(mid) > windowStart) {
        hi = mid;
      } else {
        lo = mid + 1;
      }
    }
    return lo < this.size ? this.at(lo) : null;
  }

  /** Access logical index (0 = oldest) */
  private at(logicalIndex: number): number {
    const start = this.size < this.buf.length
      ? 0
      : this.head; // when full, head points to oldest
    return this.buf[(start + logicalIndex) % this.buf.length]!;
  }

  clear(): void {
    this.head = 0;
    this.size = 0;
  }
}

/**
 * Sliding window rate limiter for tool calls.
 *
 * Uses circular buffers for O(1) push and O(log n) count operations
 * instead of array filtering. Window size defaults to 1 minute.
 */
export class RateLimiter {
  private readonly windowMs: number;
  private readonly maxEntries: number;
  private readonly buffers = new Map<string, CircularTimestampBuffer>();
  private globalBuffer: CircularTimestampBuffer;

  constructor(options?: { windowMs?: number; maxEntries?: number }) {
    this.windowMs = options?.windowMs ?? RATE_LIMIT_WINDOW_MS;
    this.maxEntries = options?.maxEntries ?? RATE_LIMIT_MAX_ENTRIES;
    this.globalBuffer = new CircularTimestampBuffer(this.maxEntries);
  }

  /**
   * Checks if a tool call is within the rate limit.
   * Does NOT record the call - use recordCall() after successful execution.
   */
  checkLimit(
    toolName: string,
    limitPerWindow: number,
  ): RateLimitResult {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    const buffer = this.buffers.get(toolName);
    if (!buffer) {
      return { allowed: true, remaining: limitPerWindow, resetAt: now + this.windowMs };
    }

    const count = buffer.countAfter(windowStart);
    const allowed = count < limitPerWindow;
    const remaining = Math.max(0, limitPerWindow - count);
    const oldest = buffer.oldestInWindow(windowStart);
    const resetAt = oldest !== null ? oldest + this.windowMs : now + this.windowMs;

    return { allowed, remaining, resetAt };
  }

  /**
   * Checks the global rate limit across all tools.
   */
  checkGlobalLimit(limitPerWindow: number): RateLimitResult {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    const count = this.globalBuffer.countAfter(windowStart);
    const allowed = count < limitPerWindow;
    const remaining = Math.max(0, limitPerWindow - count);
    const oldest = this.globalBuffer.oldestInWindow(windowStart);
    const resetAt = oldest !== null ? oldest + this.windowMs : now + this.windowMs;

    return { allowed, remaining, resetAt };
  }

  /**
   * Atomically checks and records a tool call.
   * Prevents TOCTOU race conditions between check and record.
   * Returns the rate limit result; if allowed, the call is already recorded.
   */
  checkAndRecord(
    toolName: string,
    limitPerWindow: number,
    globalLimit?: number,
  ): RateLimitResult {
    // Check per-tool limit
    const result = this.checkLimit(toolName, limitPerWindow);
    if (!result.allowed) {
      return result;
    }

    // Check global limit if provided
    if (globalLimit !== undefined) {
      const globalResult = this.checkGlobalLimit(globalLimit);
      if (!globalResult.allowed) {
        return globalResult;
      }
    }

    // Atomically record since we've confirmed it's allowed
    this.recordCall(toolName);
    return result;
  }

  /**
   * Records a tool call for rate limiting.
   * Call this after successful execution.
   */
  recordCall(toolName: string): void {
    const now = Date.now();

    // Per-tool tracking — lazily create buffer
    let buffer = this.buffers.get(toolName);
    if (!buffer) {
      // Per-tool buffer: cap at window limit (default 60/min is typical)
      buffer = new CircularTimestampBuffer(Math.min(this.maxEntries, 1000));
      this.buffers.set(toolName, buffer);
    }
    buffer.push(now);

    // Global tracking
    this.globalBuffer.push(now);
  }

  /**
   * Gets usage stats for a tool.
   */
  getUsage(toolName: string): { count: number; windowStart: number } {
    const now = Date.now();
    const windowStart = now - this.windowMs;
    const buffer = this.buffers.get(toolName);
    const count = buffer ? buffer.countAfter(windowStart) : 0;
    return { count, windowStart };
  }

  /**
   * Resets rate tracking for a specific tool.
   */
  resetTool(toolName: string): void {
    this.buffers.delete(toolName);
  }

  /**
   * Resets all rate tracking.
   */
  resetAll(): void {
    this.buffers.clear();
    this.globalBuffer = new CircularTimestampBuffer(this.maxEntries);
  }
}
