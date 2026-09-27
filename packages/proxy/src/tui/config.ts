/**
 * Optional TUI preferences, read once from ~/.solongate/tui-config.json:
 *   { "notifications": true, "accent": "cyan", "pollMs": 2000 }
 * All fields optional. Missing file → defaults.
 */
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export interface TuiConfig {
  notifications: boolean;
  accent?: string;
  pollMs?: number;
}

let cached: TuiConfig | null = null;

export function loadConfig(): TuiConfig {
  if (cached) return cached;
  const defaults: TuiConfig = { notifications: true };
  try {
    const raw = readFileSync(join(homedir(), '.solongate', 'tui-config.json'), 'utf-8');
    const j = JSON.parse(raw) as Partial<TuiConfig>;
    cached = {
      notifications: j.notifications !== false,
      accent: typeof j.accent === 'string' ? j.accent : undefined,
      pollMs: typeof j.pollMs === 'number' ? j.pollMs : undefined,
    };
  } catch {
    cached = defaults;
  }
  return cached;
}
