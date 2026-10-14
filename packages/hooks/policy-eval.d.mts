export interface EvalPolicy {
  mode?: string;
  rules?: readonly unknown[];
}

export function evaluate(
  policy: EvalPolicy | null | undefined,
  args: unknown,
  toolName: string,
  cwd?: string,
): string | null;

export function guessPermission(toolName: string): string;
export function matchGlob(str: string, pattern: string): boolean;
export function matchPathGlob(path: string, pattern: string): boolean;
export function scanStrings(obj: unknown): string[];
export function normalizeArgs(args: unknown): unknown;
export function extractFilenames(args: unknown): string[];
export function extractUrls(args: unknown): string[];
export function extractCommands(args: unknown): string[];
export function extractPipelines(args: unknown): string[];
export function extractPaths(args: unknown, isExec: boolean): string[];
export function patternsOf(constraint: unknown): string[] | null;
export function permissionApplies(rule: unknown, toolName: string): boolean;
export function ruleMatches( rule: unknown, args: unknown, isExec: boolean): { kind: string; value: string; pattern: string } | null;