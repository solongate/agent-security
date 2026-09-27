import type { PolicyRule } from '../core/index.js';

type CommandConstraints = NonNullable<PolicyRule['commandConstraints']>;

/**
 * Known argument field names that typically contain commands or shell-like content.
 * Used to extract commands from tool call arguments for constraint matching.
 */
const COMMAND_FIELDS = new Set([
  'command',
  'cmd',
  'query',
  'code',
  'script',
  'shell',
  'exec',
  'sql',
  'expression',
  'function',
]);

/**
 * Heuristic patterns that indicate a string value is likely a command/shell expression,
 * even when the field name is not in COMMAND_FIELDS.
 */
const COMMAND_HEURISTICS = [
  /^(sh|bash|cmd|powershell|zsh|fish)\s+-c\s+/i, // shell -c "..."
  /^(sudo|doas)\s+/i,                              // privilege escalation
  /^\w+\s+&&\s+/,                                   // cmd1 && cmd2
  /^\w+\s*\|\s*\w+/,                                // cmd1 | cmd2
  /^\w+\s*;\s*\w+/,                                 // cmd1; cmd2
  /^(curl|wget|nc|ncat)\s+/i,                       // network commands
  /^(rm|del|rmdir)\s+/i,                            // destructive commands
  /^(cat|type|more|less)\s+.*[/\\]/i,               // file read commands with paths
  /^(eval|source)\s+/i,                             // eval/source wrappers
  /^(printenv|env|set)\b/i,                         // environment variable leak
  /^(cat|head|tail|more|less|strings|xxd|od|hexdump|bat)\s+/i, // file read commands
];

/**
 * Regex to match subshell wrapper patterns like `bash -c '...'`, `sh -c "..."`, `eval "..."`.
 * Extracts the inner command for recursive constraint checking.
 */
const SUBSHELL_WRAPPERS = [
  /^(?:sh|bash|zsh|fish|dash|ksh)\s+-c\s+['"](.+?)['"]\s*$/i,
  /^(?:sh|bash|zsh|fish|dash|ksh)\s+-c\s+(.+)$/i,
  /^eval\s+['"](.+?)['"]\s*$/i,
  /^eval\s+(.+)$/i,
  /^(?:sh|bash|zsh|fish|dash|ksh)\s+<<\s*['"]?(\w+)['"]?\n([\s\S]+?)\n\1$/i,
];

const MAX_RECURSION_DEPTH = 8;

/**
 * Extracts inner commands from subshell wrappers (bash -c, eval, etc.)
 * Returns the original command plus any extracted inner commands.
 */
export function extractInnerCommands(command: string, depth = 0): string[] {
  const results = [command];
  if (depth >= MAX_RECURSION_DEPTH) return results;
  const trimmed = command.trim();

  for (const pattern of SUBSHELL_WRAPPERS) {
    const match = trimmed.match(pattern);
    if (match) {
      // For heredoc pattern, inner command is in group 2
      const inner = (match[2] ?? match[1] ?? '').trim();
      if (inner) {
        results.push(inner);
        // Recurse: inner command might also be a wrapper
        const nested = extractInnerCommands(inner, depth + 1);
        for (const n of nested) {
          if (n !== inner) results.push(n);
        }
      }
      break;
    }
  }

  // Also handle string concatenation patterns that build commands:
  // variable=value && ... && command "$variable"
  // Look for the final command after the last && or ;
  const chainParts = trimmed.split(/\s*(?:&&|;)\s*/);
  if (chainParts.length > 1) {
    for (const part of chainParts) {
      const p = part.trim();
      if (p && p !== trimmed && !p.includes('=')) {
        results.push(p);
      }
    }
  }

  return [...new Set(results)];
}

/**
 * Extracts command-like arguments from tool call arguments.
 * Uses known field names plus heuristic detection for command-like strings
 * in any field, and recurses into nested objects/arrays.
 */
export function extractCommandArguments(
  args: Readonly<Record<string, unknown>>,
): string[] {
  const commands: string[] = [];
  const seen = new Set<string>();

  function addCommand(value: string): void {
    const trimmed = value.trim();
    if (trimmed && !seen.has(trimmed)) {
      seen.add(trimmed);
      commands.push(trimmed);
    }
  }

  function scanValue(key: string, value: unknown): void {
    if (typeof value === 'string') {
      // Known command field names — always extract
      if (COMMAND_FIELDS.has(key.toLowerCase())) {
        addCommand(value);
        return;
      }
      // Deep scan: heuristic detection of command-like strings
      for (const pattern of COMMAND_HEURISTICS) {
        if (pattern.test(value)) {
          addCommand(value);
          return;
        }
      }
    }
    // Recurse into arrays and objects
    if (Array.isArray(value)) {
      for (const item of value) {
        scanValue(key, item);
      }
    } else if (typeof value === 'object' && value !== null) {
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        scanValue(k, v);
      }
    }
  }

  for (const [key, value] of Object.entries(args)) {
    scanValue(key, value);
  }

  // Extract inner commands from subshell wrappers (bash -c, eval, etc.)
  const expanded: string[] = [];
  for (const cmd of commands) {
    for (const inner of extractInnerCommands(cmd)) {
      if (!seen.has(inner)) {
        seen.add(inner);
        expanded.push(inner);
      }
    }
  }
  commands.push(...expanded);

  return commands;
}

/**
 * Glob-style command pattern matching.
 * Matches against the command string (first word) or full command line.
 *
 * Patterns:
 *   'ls'       → exact match on command name
 *   'git*'     → command starts with 'git'
 *   '*sql*'    → command contains 'sql'
 *   'rm -rf *' → full command line starts with 'rm -rf '
 */
export function matchCommandPattern(command: string, pattern: string): boolean {
  if (pattern === '*') return true;

  const normalizedCommand = command.trim().toLowerCase();
  const normalizedPattern = pattern.trim().toLowerCase();

  if (normalizedPattern === normalizedCommand) return true;

  const startsWithStar = normalizedPattern.startsWith('*');
  const endsWithStar = normalizedPattern.endsWith('*');

  if (startsWithStar && endsWithStar) {
    const infix = normalizedPattern.slice(1, -1);
    return infix.length > 0 && normalizedCommand.includes(infix);
  }
  if (endsWithStar) {
    const prefix = normalizedPattern.slice(0, -1);
    return normalizedCommand.startsWith(prefix);
  }
  if (startsWithStar) {
    const suffix = normalizedPattern.slice(1);
    return normalizedCommand.endsWith(suffix);
  }

  // Also try matching just the command name (first word)
  const commandName = normalizedCommand.split(/\s+/)[0] ?? '';
  return commandName === normalizedPattern;
}

/**
 * Checks if a command is allowed by the given constraints.
 *
 * Evaluation order:
 * 1. If denied list exists, command must NOT match any denied pattern
 * 2. If allowed list exists, command must match at least one allowed pattern
 * 3. If neither list exists, command is allowed (constraints are optional)
 */
export function isCommandAllowed(
  command: string,
  constraints: CommandConstraints,
): boolean {
  // 1. Denied list — any match means denied
  if (constraints.denied && constraints.denied.length > 0) {
    for (const pattern of constraints.denied) {
      if (matchCommandPattern(command, pattern)) {
        return false;
      }
    }
  }

  // 2. Allowed list — must match at least one
  if (constraints.allowed && constraints.allowed.length > 0) {
    let matchesAllowed = false;
    for (const pattern of constraints.allowed) {
      if (matchCommandPattern(command, pattern)) {
        matchesAllowed = true;
        break;
      }
    }
    if (!matchesAllowed) return false;
  }

  return true;
}
