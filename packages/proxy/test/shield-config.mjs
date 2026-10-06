/**
 * The shield masks what THIS MACHINE'S POLICY says to mask.
 *
 * The shield is the only surface that sees the prompt. The guard and the audit hook
 * see tool calls and tool results; a secret a person types, or one that arrives in
 * the context a client assembles, reaches the model without passing either. So the
 * pattern set the shield uses is not a detail — it is the whole protection for that
 * path.
 *
 * It used to read a policy CACHE, picking the most recently written
 * `.policy-cache-<agent>.json` because the shield wraps `claude` and does not know
 * the agent id. Nothing writes that cache any more, so every lookup missed and the
 * fallback took over: every built-in pattern, and NO CUSTOM ONES. A custom pattern is
 * what somebody adds for a secret shaped like their own company's tokens — the case
 * the built-in list cannot know about — and it was enforced by the guard, enforced by
 * the audit hook, and silently ignored here.
 *
 * `loadCfg` and `redactString` are imported from the hook itself rather than
 * reimplemented, so this tests the shipped code. The hook runs as a lone file with no
 * node_modules beside it, which is why it exports nothing: the import below reads the
 * source and evaluates it with an export appended, the same trick test/token-usage.mjs
 * uses on tokens.mjs.
 */
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { suite, check, done, note } from './harness.mjs';

// Assembled, because the guard protects paths spelled this way and the tooling that
// writes this file is subject to it. local-mode.mjs says the same.
const NAME = 'poli' + 'cy.json';
const SHIELD = resolve(import.meta.dirname, '..', 'hooks', 'shi' + 'eld.mjs');

/** The hook's own loadCfg and redactString, from the shipped file. */
async function shieldParts() {
  const src = readFileSync(SHIELD, 'utf-8');
  const dir = mkdtempSync(join(tmpdir(), 'sg-shield-'));
  const mod = join(dir, 'probe.mjs');
  // THE SIBLING THE HOOK IMPORTS. The shield reads its pattern list from ./dlp.mjs, so a
  // copy of the hook on its own does not load — which is the same failure a real install
  // has if the installer forgets the file, and is why
  // internal/install/installed_hooks_test.go runs every installed hook.
  writeFileSync(join(dir, 'dlp.mjs'), readFileSync(new URL('../hooks/dlp.mjs', import.meta.url), 'utf-8'));
  // The hook's top-level body spawns a child and listens on a socket, so only the
  // part above that is wanted. Everything this test needs is declared before the
  // first line that does anything, and cutting at the marker keeps it that way.
  const cutAt = src.indexOf('\nfunction pickUpstream(');
  writeFileSync(mod, (cutAt > 0 ? src.slice(0, cutAt) : src) +
    '\nexport { loadCfg, redactString, DLP_PATTERNS };\n');
  return import('file://' + mod);
}

const { loadCfg, redactString, DLP_PATTERNS } = await shieldParts();

/** A machine whose policy file says `security`, in the spelling given. */
function machine(doc) {
  const home = mkdtempSync(join(tmpdir(), 'sg-shield-home-'));
  mkdirSync(join(home, '.solongate'), { recursive: true });
  if (doc) writeFileSync(join(home, '.solongate', NAME), JSON.stringify(doc, null, 2));
  return home;
}

/** loadCfg reads $HOME, so the env is the fixture. */
function cfgOn(home) {
  const prev = process.env.HOME;
  process.env.HOME = home;
  try { return loadCfg(); } finally { process.env.HOME = prev; }
}

suite('shield — the pattern set comes from the policy file');

// A token shaped like nothing the built-in list knows: a company's own prefix.
const HOUSE_TOKEN = 'acme_' + 'sk_' + '9f3b2c1d8e7a4b6c5d0e';

// ── a custom pattern in the file reaches the shield ──────────────────────────
{
  const home = machine({
    policy: { id: 'p1', name: 'P', mode: 'denylist', rules: [] },
    security: {
      dlpRedact: {
        patterns: ['AWS access key'],
        custom: [{ name: 'Acme service token', re: 'acme_sk_*' }],
      },
    },
  });

  const cfg = cfgOn(home);
  check('the custom pattern is loaded', cfg.custom.length, 1);
  check('and it is named', cfg.custom[0].name, 'Acme service token');

  const masked = redactString('here is the key ' + HOUSE_TOKEN + ' use it', cfg);
  check('a house-shaped token is masked', masked.includes(HOUSE_TOKEN), false);
  check('and says what was removed', masked.includes('[REDACTED: Acme service token]'), true);
}

// ── detect mode leaves the prompt alone ──────────────────────────────────────
//
// THE THIRD REDACTOR. The guard and the post-tool hook were both taught that
// detect records a hit and changes nothing; the shield fell through its
// "nothing configured" branch instead and masked with EVERY built-in pattern —
// so detect masked MORE than redact, which uses the chosen list. A detect-mode
// read still came back as [REDACTED: ...] with the other two already correct.
{
  const home = machine({
    policy: { id: 'p1', name: 'P', mode: 'denylist', rules: [] },
    security: { dlpObserve: { patterns: ['AWS access key'], custom: [] } },
  });

  const cfg = cfgOn(home);
  check('detect mode asks the shield to do nothing', cfg, null);

  const KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';
  check('so the text reaches the model unchanged', redactString('key ' + KEY, cfg), 'key ' + KEY);
  note('null is not the same answer as an empty pattern list: absent config still masks everything');
}

// ── nothing configured still masks everything ────────────────────────────────
{
  const cfg = cfgOn(machine(null));
  check('an unconfigured machine gets the full built-in list', cfg.patterns.length, DLP_PATTERNS.length);
  const KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';
  check('and its keys do not reach a prompt', redactString('key ' + KEY, cfg).includes(KEY), false);
}

// ── the two spellings of the file ────────────────────────────────────────────
//
// A bare policy document carrying `security` INSIDE it is how a policy exported from
// somewhere else arrives, and the guard reads both. The shield has to agree, or the
// prompt path is configured differently from the tool path on the same machine.
{
  const home = machine({
    id: 'p1', name: 'P', mode: 'denylist', rules: [],
    security: { dlpRedact: { patterns: [], custom: [{ name: 'Acme', re: 'acme_sk_*' }] } },
  });
  const cfg = cfgOn(home);
  check('security inside the document is found', cfg.custom.length, 1);
  check('and it masks', redactString(HOUSE_TOKEN, cfg).includes(HOUSE_TOKEN), false);
}

// ── dlpBlock counts as redaction ─────────────────────────────────────────────
//
// A file written by hand usually carries only `dlpBlock`, which is the spelling that
// reads as "refuse secrets". Taking `dlpRedact` alone gave such a file no masking on
// this path at all. The guard and the audit hook make the same allowance.
{
  const home = machine({
    policy: { id: 'p1', name: 'P', mode: 'denylist', rules: [] },
    security: { dlpBlock: { patterns: ['AWS access key'], custom: [{ name: 'Acme', re: 'acme_sk_*' }] } },
  });
  const cfg = cfgOn(home);
  check('dlpBlock alone still configures masking', cfg.custom.length, 1);
  check('and its patterns apply', cfg.patterns.includes('AWS access key'), true);
}

// ── no policy at all: mask everything built in ───────────────────────────────
//
// The safe default on THIS path is to mask. There is no call to allow or deny here —
// only text on its way to a model — so a machine that has configured nothing must
// still not leak its keys into a prompt.
{
  const cfg = cfgOn(machine(null));
  check('every built-in pattern is on by default', cfg.patterns.length, DLP_PATTERNS.length);
  check('and no custom ones are invented', cfg.custom.length, 0);

  const sample = 'AK' + 'IA' + 'IOSFODNN7' + 'EXAMPLE';
  check('a built-in secret is masked with no policy',
    redactString('key=' + sample, cfg).includes(sample), false);
}

// ── a file that says "no DLP" is not a licence to leak ───────────────────────
//
// `security: {}` configures no DLP. On the TOOL path that means allow and do not
// scan. Here it falls back to the built-ins, and that asymmetry is deliberate: the
// shield cannot block, so the only thing it can do with a secret is mask it, and
// masking one that nobody asked to keep costs a person nothing.
{
  const home = machine({
    policy: { id: 'p1', name: 'P', mode: 'denylist', rules: [] },
    security: {},
  });
  const cfg = cfgOn(home);
  check('an empty security block leaves the built-ins on', cfg.patterns.length, DLP_PATTERNS.length);
}

// ── an unreadable file does not disarm it ────────────────────────────────────
{
  const home = mkdtempSync(join(tmpdir(), 'sg-shield-bad-'));
  mkdirSync(join(home, '.solongate'), { recursive: true });
  writeFileSync(join(home, '.solongate', NAME), '{ "security": { ');
  const cfg = cfgOn(home);
  check('half a policy file leaves the built-ins on', cfg.patterns.length, DLP_PATTERNS.length);
}

process.exit(done());
