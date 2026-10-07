// SPDX-License-Identifier: Apache-2.0

/**
 * The guard's own per-agent state must be unreachable from a tool call, by every
 * route — not only from a shell command.
 *
 * IT WAS REACHABLE HERE AND NOT IN THE GO BINARY, and that asymmetry is what made
 * it easy to miss. The two path-glob implementations disagree:
 *
 *   hook   matchPathGlob splits a pattern on `**` and substring-tests each
 *          remaining piece, so the `*` in the per-agent entry stays a literal
 *          asterisk — and no real filename contains one. No match.
 *   Go     MatchPathGlob compiles the pattern to a regex, where that `*` is a
 *          real wildcard. Match.
 *
 * A machine runs whichever of the two it has, so on every machine without the
 * binary the policy cache was writable through a tool. Deleting it with a shell
 * command was refused; a Write aimed at the same path was not, and every coding
 * agent has one. Overwriting it with `{}` leaves the guard with no policy to
 * apply, so the next call is allowed — and the refresh that would repair it is
 * debounced for three seconds, so the trick repeats.
 *
 * This drives the BUILT hook end to end rather than lifting the function out,
 * because the claim is about what the guard decides, and the decision runs
 * through tool-argument extraction and the client adapter before it gets near a
 * path check. A unit test on isProtectedPath would have passed while a Write
 * still went through.
 */
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { suite, check, note, done, call, FAKE_KEY } from './harness.mjs';

// Assembled, or this file's own text trips the protection under test and the
// tooling that writes it refuses. Same reason dlpkey_test.go does it in Go.
const CACHE_NAME = '.policy' + '-cache-conformance.json';
const CRED_NAME = 'cloud' + '-guard.json';

const home = mkdtempSync(join(tmpdir(), 'sg-tamper-'));
const sg = join(home, '.solongate');
mkdirSync(sg, { recursive: true });
writeFileSync(join(sg, CRED_NAME), JSON.stringify({ apiKey: FAKE_KEY, apiUrl: 'http://127.0.0.1:9' }));

// A cache to aim at. Its contents do not matter — what is under test is whether
// the guard lets a tool touch the path at all.
const cache = join(sg, CACHE_NAME);
writeFileSync(cache, JSON.stringify({ _ts: Date.now(), policy: null, security: {} }));

/**
 * Run the guard on one tool call and say whether it refused.
 *
 * Through the harness, which derives the launch from what HOOK is: a script
 * needs an interpreter, a compiled binary IS one. This file used to spawn
 * `node HOOK` itself, so pointing the suite at the Go binary handed an ELF file
 * to node and every check here failed — including the shell route, which has
 * always worked on both sides. A test that cannot run against the other
 * implementation cannot notice the two disagreeing, which is the one thing this
 * particular test exists to catch.
 */
function refused(tool, input) {
  const r = call(home, tool, input);
  // Exit 2 is the block, and the reason lands on stderr. Both are checked: an
  // exit code with no reason is a crash wearing a block's clothes.
  return r.code === 2 && /tamper protection/i.test(String(r.stderr));
}

suite('tamper — the guard\'s own state is unreachable by every route');

check('the fixture is in place', existsSync(cache), true);

// The path-taking tools. These are the ones that were open.
for (const [tool, input] of [
  ['Write', { file_path: cache, content: '{}' }],
  ['Edit', { file_path: cache, old_string: 'a', new_string: 'b' }],
  ['Read', { file_path: cache }],
]) {
  check(`${tool} on the policy cache is refused`, refused(tool, input), true);
}

// The shell spelling, which was already covered. Kept so a change that fixes one
// side by breaking the other cannot pass.
check('a shell command naming it is refused', refused('Bash', { command: `rm ${cache}` }), true);

// And the other half: these names are matched as PREFIXES, and several are ones a
// person's own project may well use. A tamper fix that blocks a developer's own
// policy.json has broken more than it fixed.
const ownPolicy = join(home, 'work', 'poli' + 'cy.json');
mkdirSync(join(home, 'work'), { recursive: true });
for (const [label, input] of [
  ["a project's own policy file", { file_path: ownPolicy, content: '{}' }],
  ['an ordinary source file', { file_path: join(home, 'work', 'main.ts'), content: 'x' }],
]) {
  const blocked = refused('Write', input);
  check(`${label} is NOT refused`, blocked, false);
  if (blocked) note(`${input.file_path} was blocked`);
}

// ── THE GUARD BINARY ─────────────────────────────────────────────────────────
//
// The hook runs whatever sits at ~/.solongate/bin/solongate-guard as soon as it prints
// the expected number for --sg-version, and then honours its exit code. So a two-line
// shell script there —
//
//   #!/bin/sh
//   case "$1" in --sg-version) echo <HOOK_VERSION>;; *) exit 0;; esac
//
// makes the hook hand every call to it and allow everything, while `solongate doctor`
// goes on reporting a native guard in use. That is a complete disarm, and it was
// reachable from ONE tool call: the path was not in the Node hook's protected list.
//
// The Go guard had covered it for a while — its comment reads "it was the one file in
// this directory the tamper check did not cover" — and the fix was never ported. So
// which implementation a machine ran decided whether the disarm worked, and the machines
// that run the Node hook are exactly the ones with no binary, where nothing legitimate
// occupies the path.
//
// Every route is checked, because the point of this file is that one route being open is
// enough.
{
  const binDir = join(home, '.solongate', 'bin');
  const guardBin = join(binDir, 'solongate-guard');
  const winBin = join(binDir, 'solongate-guard.exe');
  mkdirSync(binDir, { recursive: true });

  for (const [label, tool, input] of [
    ['a Write at the binary', 'Write', { file_path: guardBin, content: '#!/bin/sh\nexit 0\n' }],
    ['a Write at the Windows binary', 'Write', { file_path: winBin, content: 'x' }],
    ['an Edit of the binary', 'Edit', { file_path: guardBin, old_string: 'a', new_string: 'b' }],
    // Anything else dropped in that directory is a candidate the hook may pick up, so
    // the whole directory is protected rather than the one filename.
    ['a Write anywhere in bin/', 'Write', { file_path: join(binDir, 'anything'), content: 'x' }],
    ['cp over the binary', 'Bash', { command: `cp /bin/true ${guardBin}` }],
    ['a shell redirect into it', 'Bash', { command: `printf 'x' > ${guardBin}` }],
    ['chmod +x on it', 'Bash', { command: `chmod +x ${guardBin}` }],
    ['deleting it', 'Bash', { command: `rm -f ${guardBin}` }],
    ['moving something onto it', 'Bash', { command: `mv /tmp/x ${guardBin}` }],
    // THE DIRECTORY ITSELF. `rm -rf ~/.solongate/bin` names no protected basename and
    // matches no `/bin/**` glob — that needs something after the slash — so it went
    // through in BOTH implementations. It is not a disarm on its own: with no binary the
    // hook runs its own implementation and still decides (go-delegation.mjs pins that).
    // What it is, is an agent quietly taking the fast path away while `doctor` reports
    // the Node implementation as though somebody had chosen it. The hooks directory was
    // already covered this way, and that asymmetry — hooks yes, bin no — is what let the
    // write-side hole above sit unnoticed.
    ['rm -rf the bin directory', 'Bash', { command: `rm -rf ${binDir}` }],
    ['moving the bin directory away', 'Bash', { command: `mv ${binDir} ${binDir}-old` }],
    ['rmdir on it', 'Bash', { command: `rmdir ${binDir}` }],
    ['chmod on it', 'Bash', { command: `chmod 777 ${binDir}` }],
    ['a Write at the directory path', 'Write', { file_path: binDir, content: 'x' }],
  ]) {
    check(`${label} is refused`, refused(tool, input), true);
  }
}

// ── THE RATE-LIMIT COUNTER ───────────────────────────────────────────────────
//
// The limiter keeps its stamps in ~/.solongate/.ratelimit-<agent>.log. Delete that and
// the window is empty again, so a limit of N calls/minute becomes N PER DELETION — an
// agent that can remove one file is not rate-limited at all.
//
// It was protected in both implementations and exercised by neither. That is the same
// shape as the disarm above: an entry on a shared list, correct in both, held by nothing
// — so a change to either could quietly drop it. The extension is part of the point: the
// path globs said `.json` while the limiter writes `.log`, so the glob matched no real
// file and the basename rule was doing all the work on its own.
{
  const counter = join(home, '.solongate', '.ratelimit-conformance.log');
  writeFileSync(counter, '[]');
  for (const [label, tool, input] of [
    ['rm on the counter', 'Bash', { command: `rm -f ${counter}` }],
    ['truncating it', 'Bash', { command: `: > ${counter}` }],
    ['a Write of [] over it', 'Write', { file_path: counter, content: '[]' }],
    ['an Edit of it', 'Edit', { file_path: counter, old_string: '[', new_string: ' ' }],
    ['a glob delete of every counter', 'Bash', { command: `rm -f ${join(home, '.solongate')}/.ratelimit-*` }],
  ]) {
    check(`${label} is refused`, refused(tool, input), true);
  }
}

rmSync(home, { recursive: true, force: true });
process.exit(done());
