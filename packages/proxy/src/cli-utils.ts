/**
 * Shared CLI utilities for SolonGate proxy CLI commands.
 * Consolidates banner art, ANSI colors, and log helpers used by init, inject, and create.
 */

// ── ANSI Colors ─────────────────────────────────────────────────────────

export const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  italic: '\x1b[3m',
  white: '\x1b[97m',
  gray: '\x1b[90m',
  blue1: '\x1b[38;2;20;50;160m',
  blue2: '\x1b[38;2;40;80;190m',
  blue3: '\x1b[38;2;60;110;215m',
  blue4: '\x1b[38;2;90;140;230m',
  blue5: '\x1b[38;2;130;170;240m',
  blue6: '\x1b[38;2;170;200;250m',
  green: '\x1b[38;2;80;200;120m',
  red: '\x1b[38;2;220;80;80m',
  cyan: '\x1b[38;2;100;200;220m',
  yellow: '\x1b[38;2;220;200;80m',
  bgBlue: '\x1b[48;2;20;50;160m',
};

// ── Log Helper ──────────────────────────────────────────────────────────

export function log(msg: string): void {
  process.stderr.write(msg + '\n');
}

// ── Banner Art ──────────────────────────────────────────────────────────

export const BANNER_FULL = [
  ' ███████╗ ██████╗ ██╗      ██████╗ ███╗   ██╗ ██████╗  █████╗ ████████╗███████╗',
  ' ██╔════╝██╔═══██╗██║     ██╔═══██╗████╗  ██║██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝',
  ' ███████╗██║   ██║██║     ██║   ██║██╔██╗ ██║██║  ███╗███████║   ██║   █████╗  ',
  ' ╚════██║██║   ██║██║     ██║   ██║██║╚██╗██║██║   ██║██╔══██║   ██║   ██╔══╝  ',
  ' ███████║╚██████╔╝███████╗╚██████╔╝██║ ╚████║╚██████╔╝██║  ██║   ██║   ███████╗',
  ' ╚══════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝',
];

export const BANNER_COLORS = [c.blue1, c.blue2, c.blue3, c.blue4, c.blue5, c.blue6];

export function printBanner(subtitle: string): void {
  log('');
  for (let i = 0; i < BANNER_FULL.length; i++) {
    log(`${c.bold}${BANNER_COLORS[i]}${BANNER_FULL[i]}${c.reset}`);
  }
  log('');
  log(`  ${c.dim}${c.italic}${subtitle}${c.reset}`);
  log('');
}
