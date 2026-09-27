/**
 * Runs every conformance file and reports one verdict.
 *
 * Each file is its own process: they spawn guards, start stub servers and write
 * to temp homes, and a shared process would let one file's leftovers decide
 * another file's result.
 */
import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const skip = new Set(['run-all.mjs', 'harness.mjs']);
const files = readdirSync(here).filter((f) => f.endsWith('.mjs') && !skip.has(f)).sort();

console.log(`guard under test: ${process.env.SG_HOOK || '(installed hook)'}`);

const failed = [];
for (const f of files) {
  const r = spawnSync(process.execPath, [join(here, f)], { stdio: 'inherit', timeout: 300000 });
  if (r.status !== 0) failed.push(f);
}

console.log('\n' + '─'.repeat(60));
if (failed.length === 0) {
  console.log(`${files.length} file(s) passed.`);
  process.exit(0);
}
console.log(`FAILED: ${failed.join(', ')}`);
process.exit(1);
