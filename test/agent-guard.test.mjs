import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const exe = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'agent-guard.mjs');
function sandbox(fn) {
  const root = mkdtempSync(join(tmpdir(), 'safepush-guard-'));
  try { fn(root); } finally { rmSync(root, { recursive: true, force: true }); }
}
function gate(root, tool_name, tool_input) {
  const r = spawnSync(process.execPath, [exe, '--root', root], {
    input: JSON.stringify({ tool_name, tool_input }), encoding: 'utf8', timeout: 15000,
  });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim() ? JSON.parse(r.stdout) : null;
}
function denied(v) {
  assert.equal(v?.hookSpecificOutput?.permissionDecision, 'deny');
}
test('allows reading ordinary project file without revealing content', () => sandbox(root => {
  writeFileSync(join(root, 'index.js'), 'console.log("hello");');
  assert.equal(gate(root, 'Read', { file_path: join(root, 'index.js') }), null);
}));
test('denies env, private keys and credential files', () => sandbox(root => {
  for (const file of ['.env', '.env.production', 'id_ed25519', 'settings.pem', '.npmrc', 'credentials.json']) {
    writeFileSync(join(root, file), 'SYNTHETIC_ONLY');
    denied(gate(root, 'Read', { file_path: join(root, file) }));
    denied(gate(root, 'Write', { file_path: join(root, file), content: 'x' }));
  }
}));
test('denies every Bash, search, unknown and MCP tool regardless of arguments', () => sandbox(root => {
  for (const tool of ['Bash', 'Grep', 'Glob', 'NotebookRead', 'Task', 'Agent', 'mcp__filesystem__read_file']) {
    denied(gate(root, tool, { command: 'echo ok', path: root }));
  }
}));
test('denies traversal, external paths and missing reads', () => sandbox(root => {
  const outside = mkdtempSync(join(tmpdir(), 'safepush-outside-'));
  try {
    writeFileSync(join(outside, 'public.js'), 'dummy');
    denied(gate(root, 'Read', { file_path: join(outside, 'public.js') }));
    denied(gate(root, 'Read', { file_path: '../elsewhere.js' }));
    denied(gate(root, 'Read', { file_path: 'missing.js' }));
    denied(gate(root, 'Read', {}));
  } finally { rmSync(outside, { recursive: true, force: true }); }
}));
test('denies symlink to external secret when symlinks can be created', t => sandbox(root => {
  const outside = mkdtempSync(join(tmpdir(), 'safepush-outside-'));
  try {
    writeFileSync(join(outside, 'private.txt'), 'SYNTHETIC');
    try { symlinkSync(join(outside, 'private.txt'), join(root, 'linked.js')); }
    catch (e) { if (process.platform === 'win32' && ['EPERM', 'EACCES', 'ENOTSUP'].includes(e.code)) { t.skip('No Windows symlink privilege'); return; } throw e; }
    denied(gate(root, 'Read', { file_path: join(root, 'linked.js') }));
    denied(gate(root, 'Write', { file_path: join(root, 'linked.js'), content: 'x' }));
  } finally { rmSync(outside, { recursive: true, force: true }); }
}));
test('denies malformed hook input and never echoes it', () => sandbox(root => {
  const r = spawnSync(process.execPath, [exe, '--root', root], { input: '{secret-do-not-echo}', encoding: 'utf8' });
  assert.equal(r.status, 0);
  assert.ok(!r.stdout.includes('secret-do-not-echo'));
  denied(JSON.parse(r.stdout));
}));
