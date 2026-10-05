/**
 * Types for policy-eval.mjs, which is plain JavaScript on purpose.
 *
 * The hook is the demanding consumer: it has to run as a lone file with no
 * node_modules beside it, so the shared evaluator lives in hooks/ as .mjs and
 * esbuild inlines it. This declaration is how the TypeScript side — the MCP
 * proxy's policy engine — imports the same code rather than carrying a second
 * evaluator that would drift from the guard's.
 *
 * Kept deliberately loose where the runtime is loose. A rule's `rules` array is
 * whatever the policy document holds, because a field this version does not know
 * about has to survive being read and written back; narrowing it here would be a
 * promise the .mjs does not make.
 */

/** A policy as the guard reads one: a rule list and a mode. */
export interface EvalPolicy {
  mode?: string;
  rules?: readonly unknown[];
}

/**
 * Decide one call.
 *
 * Answers the REASON it is refused, or null when nothing here forbids it. Null is
 * not "a rule allowed this": in denylist mode nothing matching is the normal
 * outcome, and in whitelist mode a call that matches no ALLOW rule comes back
 * with a reason precisely because silence would be the wrong answer.
 */
export function evaluate(
  policy: EvalPolicy | null | undefined,
  args: unknown,
  toolName: string,
  /**
   * The directory the call was made from. A relative path token in a shell
   * command only names a file once it is resolved against this; without it an
   * absolute path rule is walked past by `cat forbidden/notes.txt`. Optional
   * because a caller that has no cwd is better off matching literally than
   * guessing one.
   */
  cwd?: string,
): string | null;

/** Which class of call a tool name is, the way every rule's `permission` reads it. */
export function guessPermission(toolName: string): string;

export function matchGlob(str: string, pattern: string): boolean;
export function matchPathGlob(path: string, pattern: string): boolean;
export function scanStrings(obj: unknown): string[];
export function normalizeArgs(args: unknown): unknown;
export function extractFilenames(args: unknown): string[];
export function extractUrls(args: unknown): string[];
export function extractCommands(args: unknown): string[];
/** Like extractCommands, but a pipeline stays one string — see the .mjs. */
export function extractPipelines(args: unknown): string[];
export function extractPaths(args: unknown, isExec: boolean): string[];
export function patternsOf(constraint: unknown): string[] | null;
export function permissionApplies(rule: unknown, toolName: string): boolean;
export function ruleMatches(
  rule: unknown,
  args: unknown,
  isExec: boolean,
): { kind: string; value: string; pattern: string } | null;
