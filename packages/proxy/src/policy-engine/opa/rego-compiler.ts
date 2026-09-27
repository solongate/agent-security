// Rego Compiler: compiles Rego source into WASM bundles using the opa CLI.
import { execFileSync } from 'node:child_process';
import { writeFileSync, readFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';

// Compiles Rego source code into a WASM bundle using the `opa` CLI.
// This is a build-time operation — not called at runtime.
// The resulting WASM bundle is stored in the database and loaded by the sentinel.
// Requires `opa` CLI to be available in PATH or at the path specified
// by the SOLONGATE_OPA_PATH environment variable.
// @param regoSource - The Rego policy source code
// @param entrypoint - The Rego entrypoint (default: "solongate/policy/decision")
// @returns Buffer containing the compiled WASM bundle (.tar.gz)
export async function compileRegoToWasm(
  regoSource: string,
  entrypoint = 'solongate/policy/decision',
): Promise<Buffer> {
  const opaPath = process.env.SOLONGATE_OPA_PATH || 'opa';
  const workDir = join(tmpdir(), `solongate-opa-${randomUUID()}`);

  try {
    mkdirSync(workDir, { recursive: true });

    // Write the Rego source to a temporary file
    const regoFile = join(workDir, 'policy.rego');
    writeFileSync(regoFile, regoSource, 'utf-8');

    // Also write helper functions that the generated Rego may reference
    const helpersFile = join(workDir, 'helpers.rego');
    writeFileSync(helpersFile, REGO_HELPERS, 'utf-8');

    const bundleFile = join(workDir, 'bundle.tar.gz');

    // Compile Rego to WASM using opa build
    execFileSync(opaPath, [
      'build',
      '-t', 'wasm',
      '-e', entrypoint,
      '-o', bundleFile,
      workDir,
    ], {
      timeout: 30_000,
      stdio: 'pipe',
    });

    return readFileSync(bundleFile);
  } finally {
    // Clean up temp directory
    try {
      rmSync(workDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  }
}

// Checks if the OPA CLI is available.
export function isOpaAvailable(): boolean {
  const opaPath = process.env.SOLONGATE_OPA_PATH || 'opa';
  try {
    execFileSync(opaPath, ['version'], { timeout: 5_000, stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

// Helper Rego functions used by the generated policy code.
// These are written to a separate file and compiled alongside the policy.
const REGO_HELPERS = `package solongate.policy

import rego.v1

# Helper: checks if a path matches any pattern in a list using glob
path_matches_any(path, patterns) if {
    some pattern in patterns
    glob.match(pattern, ["/"], path)
}

# Helper: checks if an item matches any pattern in a list using glob
list_matches_any(item, patterns) if {
    some pattern in patterns
    glob.match(pattern, [], item)
}
`;