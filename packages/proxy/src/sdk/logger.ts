import type { ExecutionResult } from '../core/index.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LOG_LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

/**
 * Structured security event logger.
 * Outputs JSON-formatted log entries for machine consumption.
 */
export class SecurityLogger {
  private readonly minLevel: LogLevel;
  private readonly enabled: boolean;

  constructor(options: { level: LogLevel; enabled: boolean }) {
    this.minLevel = options.level;
    this.enabled = options.enabled;
  }

  logDecision(result: ExecutionResult): void {
    if (!this.enabled) return;

    const entry = {
      type: 'security_decision',
      status: result.status,
      toolName: result.request.toolName,
      permission: result.request.requiredPermission,
      trustLevel: result.request.context.trustLevel,
      requestId: result.request.context.requestId,
      timestamp: result.timestamp,
      ...(result.status === 'ALLOWED' && { durationMs: result.durationMs }),
      ...(result.status === 'DENIED' && { reason: result.decision.reason }),
      ...(result.status === 'ERROR' && { error: result.error.code }),
    };

    if (result.status === 'DENIED' || result.status === 'ERROR') {
      this.log('warn', entry);
    } else {
      this.log('info', entry);
    }
  }

  private log(level: LogLevel, data: Record<string, unknown>): void {
    if (LOG_LEVEL_ORDER[level] < LOG_LEVEL_ORDER[this.minLevel]) return;

    const output = JSON.stringify({ level, ...data });
    switch (level) {
      case 'error':
        console.error(`[SolonGate] ${output}`);
        break;
      case 'warn':
        console.warn(`[SolonGate] ${output}`);
        break;
      case 'debug':
        console.debug(`[SolonGate] ${output}`);
        break;
      default:
        console.info(`[SolonGate] ${output}`);
    }
  }
}
