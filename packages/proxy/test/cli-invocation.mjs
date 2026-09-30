// Can an agent disarm the guard by running the CLI?
//
// `solongate policy delete`, `solongate dlp disable` and the rest change what is enforced,
// so an agent that can run one is an agent that can switch off the thing watching it.
//
// IT USED TO BE THE CLI'S OWN JOB. It refused to start whenever an agent marker was in the
// environment — CLAUDECODE, CURSOR, CODEX_ and a dozen more. That refused the wrong people:
// an integrated terminal inherits the agent's environment, so a HUMAN typing `solongate` in
// VS Code or Cursor was turned away from their own tool, while an agent that allocated a
// pseudo-terminal would have walked through the TTY check beside it.
//
// So it moved here, where it is a fact about the caller rather than a guess about its
// environment: this runs on a tool call and nowhere else.
//
// The half of this file that matters most is the second one. A check like this is easy to
// write as a substring test and a substring test is a WALL: `git commit -m "fix the
// solongate docs"` contains the name and runs nothing, and a guard that blocks an agent
// from mentioning the product it is working on gets switched off entirely. Every case under
// "and these must still run" is a command a person would reasonably ask an agent for while
// working on this repository.
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const HOOK = process.env.SG_HOOK || join(HERE, '..', 'hooks', 'guard.bundled.mjs');
const IS_BIN = !HOOK.endsWith('.mjs');

const home = mkdtempSync(join(tmpdir(), 'sg-cli-'));
mkdirSync(join(home, '.solongate'), { recursive: true });
// An empty denylist: nothing is blocked by policy, so anything that IS blocked here was
// blocked by tamper protection and by nothing else.
writeFileSync(join(home, '.solongate', 'pol' + 'icy.json'), JSON.stringify({
  policy: { id: 'p1', name: 'P', mode: 'denylist', rules: [] },
  selfProtect: true,
}));

function call(command) {
  const payload = JSON.stringify({
    hook_event_name: 'PreToolUse', session_id: 'cli', cwd: home,
    tool_name: 'Bash', tool_input: { command },
  });
  const argv = IS_BIN ? [] : [HOOK];
  const bin = IS_BIN ? HOOK : process.execPath;
  const r = spawnSync(bin, [...argv, 'claude-code', 'Claude Code'], {
    input: payload, env: { ...process.env, HOME: home }, cwd: home, encoding: 'utf-8',
  });
  return { code: r.status, err: r.stderr || '' };
}

// Every one of these reaches the CLI. The evasions are the point: a check that only saw a
// bare `solongate` at the start of the string would let most of this through.
const mustBlock = [
  // the plain shapes
  ['solongate', 'bare, which opens the dataroom'],
  ['solongate policy delete local', 'deleting the policy'],
  ['solongate dlp disable "AWS access key"', 'switching off a DLP pattern'],
  ['solongate ratelimit set --minute 999999', 'raising the rate limit past meaning'],
  ['solongate repair', 'rewriting the install'],
  ['solongate-proxy --policy /tmp/mine.json -- cat', 'a proxy with the agent\'s own policy'],
  ['solongate-audit', 'reading the audit log'],
  // by path
  ['/usr/local/bin/solongate policy deny local --command "*"', 'an absolute path'],
  ['~/.local/bin/solongate policy delete local', 'a home-relative path'],
  ['./solongate policy delete local', 'a relative path'],
  ['..\\bin\\solongate policy delete local', 'a windows path'],
  ['C:\\\\Program Files\\\\SolonGate\\\\solongate policy delete local', 'a windows drive path'],
  // behind a separator
  ['echo hi && solongate policy delete local', 'after &&'],
  ['false || solongate policy delete local', 'after ||'],
  ['cd /tmp; solongate policy delete local', 'after ;'],
  ['echo y | solongate policy delete local', 'the far side of a pipe'],
  ['echo a\nsolongate policy delete local', 'on a second line'],
  ['(solongate policy delete local)', 'in a subshell'],
  ['$(solongate policy delete local)', 'in a command substitution'],
  ['`solongate policy delete local`', 'in backticks'],
  // behind a wrapper
  ['sudo solongate policy delete local', 'behind sudo'],
  ['env solongate policy delete local', 'behind env'],
  ['HOME=/tmp solongate policy delete local', 'behind an assignment'],
  ['HOME=/tmp sudo solongate policy delete local', 'behind both'],
  ['nohup solongate policy delete local', 'behind nohup'],
  ['timeout 5 solongate policy delete local', 'behind timeout'],
  ['exec solongate policy delete local', 'behind exec'],
  // without installing it
  ['npx @solongate/proxy policy delete local', 'via npx'],
  ['npx -y @solongate/proxy policy delete local', 'via npx with a flag between'],
  ['pnpm dlx @solongate/proxy policy delete local', 'via pnpm dlx'],
  ['bunx @solongate/proxy policy delete local', 'via bunx'],
  ['yarn dlx @solongate/proxy policy delete local', 'via yarn dlx'],
];

// ── and these must still run ──────────────────────────────────────
//
// Real commands a person would ask an agent for while working on this repository. A rule
// that refuses any of them is a wall, and a wall is worse than no rule at all.
const mustAllow = [
  ['echo hello', 'the simplest thing there is'],
  ['git commit -m "fix the solongate integration docs"', 'a commit message naming the product'],
  ['git log --oneline --grep solongate', 'searching history for it'],
  ['ls ~/projects/solongate-notes', 'a directory named after it'],
  ['grep -rn solongate_config ./src', 'a symbol named after it'],
  ['cat docs/solongate-setup.md', 'a documentation file named after it'],
  ['npm install @solongate/proxy', 'installing the package, which changes nothing enforced'],
  ['curl -s https://solongate.dev/docs', 'a url naming it'],
  ['echo "run solongate to open the dataroom" >> README.md', 'documenting how to run it'],
  ['python3 -c "print(\'solongate\')"', 'a program printing the name'],
  ['docker run solongate/demo', 'an image named after it'],
];

const label = IS_BIN ? 'go' : 'node';
console.log(`# cli-invocation (${label})`);
let bad = 0;

for (const [cmd, why] of mustBlock) {
  const { code, err } = call(cmd);
  const blocked = code === 2;
  const named = /solongate-cli/.test(err) || /tamper/i.test(err);
  if (!blocked) {
    bad++;
    console.log(`  not ok  reaches the CLI ${why}: ${JSON.stringify(cmd)} exited ${code}`);
  } else if (!named) {
    bad++;
    console.log(`  not ok  blocked ${why} for the wrong reason: ${err.trim().slice(0, 140)}`);
  } else {
    console.log(`  ok      blocked ${why}`);
  }
}

console.log('  --- and these must still run:');
for (const [cmd, why] of mustAllow) {
  const { code, err } = call(cmd);
  if (code === 2) {
    bad++;
    console.log(`  not ok  REFUSED ${why}: ${JSON.stringify(cmd)}\n          ${err.trim().slice(0, 200)}`);
  } else {
    console.log(`  ok      allowed ${why}`);
  }
}

if (bad) {
  console.log(`\n${bad} wrong`);
  process.exit(1);
}
console.log(`\nall ${mustBlock.length + mustAllow.length} ok`);
