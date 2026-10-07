// SPDX-License-Identifier: Apache-2.0

// Emits .d.ts for the package via `tsc --emitDeclarationOnly`.
//
// The proxy sources carry pre-existing type errors that the JS build (tsup,
// which does not type-check) already ignores. `tsc` still emits valid
// declarations for them, but exits non-zero — which would abort the build
// chain. Declarations are what matter here, so we run tsc, surface its output,
// and always exit 0. Real type checking lives in the separate `typecheck`
// script.
import { spawnSync } from 'node:child_process';

const result = spawnSync(
  'tsc',
  // declarationMap off: maps would point at unpublished src/, so they are dead weight.
  ['-p', 'tsconfig.json', '--emitDeclarationOnly', '--noEmitOnError', 'false', '--declarationMap', 'false'],
  { stdio: 'inherit', shell: true },
);

if (result.status !== 0) {
  console.log('[build-types] tsc reported type errors (ignored); .d.ts emitted.');
}
process.exit(0);
