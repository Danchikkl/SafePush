import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync, writeFileSync, rmSync, realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';

const cli = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli.mjs');
const token = () => ['gh', 'p_', 'A1b2C3d4E5f6G7h8I9j0'.repeat(2)].join('');
const literal = 'Zx81Qw92Er73Ty64Ui55Op46';

function sandbox(fn) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'safepush-hook-')));
  try { return fn(dir); } finally { rmSync(dir, {recursive: true, force: true}); }
}
function git(args, cwd) {
  const p = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.test', ...args], {cwd, encoding: 'utf8'});
  if (p.status) throw new Error(p.stderr);
}
function hook(event, cwd) {
  const p = spawnSync(process.execPath, [cli, 'hook', 'claude'], {cwd, input: typeof event === 'string' ? event : JSON.stringify(event), encoding: 'utf8', timeout: 15000});
  const out = p.stdout.trim();
  return {status: p.status, stderr: p.stderr, raw: out, decision: out ? JSON.parse(out).hookSpecificOutput : null};
}
const pre = (cwd, tool_name, tool_input) => ({hook_event_name: 'PreToolUse', cwd, tool_name, tool_input, session_id: 's'});

test('denies writing a known token into source and never echoes it', () => sandbox(dir => {
  const t = token();
  const r = hook(pre(dir, 'Write', {file_path: join(dir, 'src', 'gh.ts'), content: `export const t = "${t}";\n`}), dir);
  assert.equal(r.status, 0);
  assert.equal(r.decision.hookEventName, 'PreToolUse');
  assert.equal(r.decision.permissionDecision, 'deny');
  assert.match(r.decision.permissionDecisionReason, /src\/gh\.ts/);
  assert.match(r.decision.permissionDecisionReason, /environment variable/);
  assert.ok(!r.raw.includes(t));
}));

test('asks (not denies) for heuristic findings in an Edit', () => sandbox(dir => {
  const r = hook(pre(dir, 'Edit', {file_path: join(dir, 'ai.ts'), old_string: 'x', new_string: `const OPENAI_API_KEY = "${literal}";`}), dir);
  assert.equal(r.decision.permissionDecision, 'ask');
  assert.ok(!r.raw.includes(literal));
}));

test('MultiEdit is inspected', () => sandbox(dir => {
  const r = hook(pre(dir, 'MultiEdit', {file_path: join(dir, 'a.ts'), edits: [{old_string: 'a', new_string: 'ok'}, {old_string: 'b', new_string: `const t = "${token()}";`}]}), dir);
  assert.equal(r.decision.permissionDecision, 'deny');
}));

test('clean writes produce no output', () => sandbox(dir => {
  const r = hook(pre(dir, 'Write', {file_path: join(dir, 'a.ts'), content: 'const key = process.env.OPENAI_API_KEY;\n'}), dir);
  assert.equal(r.status, 0);
  assert.equal(r.raw, '');
}));

test('secrets in an ignored .env file are allowed: that is where they belong', () => sandbox(dir => {
  git(['init', '-q'], dir);
  writeFileSync(join(dir, '.gitignore'), '.env\n.env.*\n');
  const r = hook(pre(dir, 'Write', {file_path: join(dir, '.env'), content: `GITHUB_TOKEN=${token()}\nOPENAI_API_KEY=${literal}\n`}), dir);
  assert.equal(r.raw, '');
}));

test('asks before writing an .env file that Git would not ignore', () => sandbox(dir => {
  git(['init', '-q'], dir);
  const r = hook(pre(dir, 'Write', {file_path: join(dir, '.env'), content: `OPENAI_API_KEY=${literal}\n`}), dir);
  assert.equal(r.decision.permissionDecision, 'ask');
  assert.match(r.decision.permissionDecisionReason, /would NOT ignore/);
}));

test('asks about sensitive browser-public names even in an ignored .env', () => sandbox(dir => {
  git(['init', '-q'], dir);
  writeFileSync(join(dir, '.gitignore'), '.env*\n');
  const r = hook(pre(dir, 'Write', {file_path: join(dir, '.env.local'), content: `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${literal}\n`}), dir);
  assert.equal(r.decision.permissionDecision, 'ask');
  assert.ok(!r.raw.includes(literal));
}));

test('template env files with a real-looking token are denied', () => sandbox(dir => {
  const r = hook(pre(dir, 'Write', {file_path: join(dir, '.env.example'), content: `GITHUB_TOKEN=${token()}\n`}), dir);
  assert.equal(r.decision.permissionDecision, 'deny');
}));

test('denies git commit when staged changes contain a token', () => sandbox(dir => {
  git(['init', '-q'], dir);
  writeFileSync(join(dir, 'app.js'), `const t = "${token()}";\n`);
  git(['add', 'app.js'], dir);
  const r = hook(pre(dir, 'Bash', {command: 'git add app.js && git commit -m "add app"'}), dir);
  assert.equal(r.decision.permissionDecision, 'deny');
  assert.match(r.decision.permissionDecisionReason, /app\.js:1/);
  assert.ok(!r.raw.includes(token()));
}));

test('git commit -a also checks unstaged tracked changes', () => sandbox(dir => {
  git(['init', '-q'], dir);
  writeFileSync(join(dir, 'app.js'), 'ok\n');
  git(['add', 'app.js'], dir); git(['commit', '-q', '-m', 'init'], dir);
  writeFileSync(join(dir, 'app.js'), `const t = "${token()}";\n`);
  assert.equal(hook(pre(dir, 'Bash', {command: 'git commit -m "wip"'}), dir).raw, '');
  assert.equal(hook(pre(dir, 'Bash', {command: 'git commit -am "wip"'}), dir).decision.permissionDecision, 'deny');
}));

test('clean commits are not interrupted', () => sandbox(dir => {
  git(['init', '-q'], dir);
  writeFileSync(join(dir, 'app.js'), 'console.log(1);\n');
  git(['add', 'app.js'], dir);
  assert.equal(hook(pre(dir, 'Bash', {command: 'git commit -m "clean"'}), dir).raw, '');
}));

test('denies bypassing Git hooks', () => sandbox(dir => {
  for (const command of ['git commit --no-verify -m x', 'git commit -n -m x', 'npm test && git commit --no-verify -m x']) {
    assert.equal(hook(pre(dir, 'Bash', {command}), dir).decision.permissionDecision, 'deny', command);
  }
}));

test('asks when a shell command embeds a credential', () => sandbox(dir => {
  const t = token();
  const r = hook(pre(dir, 'Bash', {command: `echo "GITHUB_TOKEN=${t}" >> .env`}), dir);
  assert.equal(r.decision.permissionDecision, 'ask');
  assert.ok(!r.raw.includes(t));
}));

test('unrelated tools and events are ignored', () => sandbox(dir => {
  assert.equal(hook(pre(dir, 'Read', {file_path: join(dir, 'x')}), dir).raw, '');
  assert.equal(hook({hook_event_name: 'PostToolUse', tool_name: 'Write', tool_input: {file_path: 'a', content: token()}}, dir).raw, '');
  assert.equal(hook(pre(dir, 'Bash', {command: 'git log --oneline'}), dir).raw, '');
}));

test('malformed input is a visible non-blocking error', () => sandbox(dir => {
  const r = hook('{not json', dir);
  assert.equal(r.status, 1);
  assert.equal(r.raw, '');
  assert.match(r.stderr, /invalid JSON/);
}));
