import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const executable = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'mcp.mjs');
const legacyInit = {
  jsonrpc: '2.0', id: 1, method: 'initialize',
  params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1.0' } },
};
const modernMeta = {
  'io.modelcontextprotocol/protocolVersion': '2026-07-28',
  'io.modelcontextprotocol/clientCapabilities': {},
  'io.modelcontextprotocol/clientInfo': { name: 'test', version: '1.0' },
};
function request(id, method, params = {}) { return { jsonrpc: '2.0', id, method, params }; }
function modernRequest(id, method, params = {}) {
  return request(id, method, { ...params, _meta: modernMeta });
}
function run(root, messages, extra = []) {
  const input = messages.map(message => JSON.stringify(message)).join('\n') + '\n';
  const p = spawnSync(process.execPath, [executable, '--root', root, ...extra], {
    encoding: 'utf8', input, timeout: 15000, maxBuffer: 2_000_000,
  });
  assert.equal(p.status, 0, p.stderr);
  const lines = p.stdout.trim().split('\n').filter(Boolean);
  return { responses: lines.map(line => JSON.parse(line)), stdout: p.stdout };
}
function sandbox(fn) {
  const root = mkdtempSync(join(tmpdir(), 'safepush-mcp-'));
  try { fn(root); } finally { rmSync(root, { recursive: true, force: true }); }
}
function git(args, cwd) {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
}
function token() { return 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0'.repeat(2); }
function payload(response) { return JSON.parse(response.result.content[0].text); }

test('legacy initialize, list and call: only JSON-RPC on stdout; no token values', () => sandbox(root => {
  const secret = token();
  writeFileSync(join(root, 'app.js'), 'const token="' + secret + '";\n');
  const { responses, stdout } = run(root, [
    legacyInit,
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    request(2, 'tools/list'),
    request(3, 'tools/call', { name: 'safepush_scan', arguments: {} }),
  ]);
  assert.equal(responses.length, 3);
  assert.equal(responses[0].result.protocolVersion, '2025-11-25');
  assert.equal(responses[1].result.tools.length, 1);
  assert.equal(responses[1].result.tools[0].name, 'safepush_scan');
  assert.deepEqual(responses[1].result.tools[0].annotations, { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false });
  assert.ok(payload(responses[2]).findings.some(f => f.rule === 'KNOWN_SECRET'));
  assert.equal(responses[2].result.isError, false);
  assert.ok(!stdout.includes(secret));
  assert.ok(!stdout.includes(root)); // absolute project path is never returned
}));

test('modern discover, tools/list and tools/call use stateless request metadata', () => sandbox(root => {
  writeFileSync(join(root, 'app.js'), 'console.log("safe");\n');
  const { responses } = run(root, [
    modernRequest(1, 'server/discover'),
    modernRequest(2, 'tools/list'),
    modernRequest(3, 'tools/call', { name: 'safepush_scan', arguments: { staged: false } }),
  ]);
  assert.equal(responses[0].result.resultType, 'complete');
  assert.ok(responses[0].result.supportedVersions.includes('2026-07-28'));
  assert.equal(responses[1].result.tools[0].name, 'safepush_scan');
  assert.equal(responses[2].result.resultType, 'complete');
  assert.equal(payload(responses[2]).filesScanned, 1);
  assert.equal(responses[2].result._meta['io.modelcontextprotocol/serverInfo'].name, 'safepush');
}));

test('staged tool reads Git index, not changed worktree', () => sandbox(root => {
  git(['init', '-q'], root);
  const secret = token();
  writeFileSync(join(root, 'app.js'), 'const token="' + secret + '";\n');
  git(['add', 'app.js'], root);
  writeFileSync(join(root, 'app.js'), 'console.log("replaced in worktree only");\n');
  const { responses, stdout } = run(root, [
    legacyInit,
    request(2, 'tools/call', { name: 'safepush_scan', arguments: { staged: true } }),
  ]);
  assert.equal(payload(responses[1]).mode, 'staged');
  assert.ok(payload(responses[1]).findings.some(f => f.rule === 'KNOWN_SECRET'));
  assert.ok(!stdout.includes(secret));
}));

test('agents cannot override pinned project root through tool arguments', () => sandbox(root => {
  const other = mkdtempSync(join(tmpdir(), 'safepush-foreign-'));
  try {
    writeFileSync(join(other, 'secret.js'), token());
    writeFileSync(join(root, 'safe.js'), 'const safe = true;\n');
    const { responses } = run(root, [
      legacyInit,
      request(2, 'tools/call', { name: 'safepush_scan', arguments: { root: other } }),
      request(3, 'tools/call', { name: 'safepush_scan', arguments: { staged: 'yes' } }),
      request(4, 'tools/call', { name: 'safepush_scan', arguments: {} }),
    ]);
    assert.equal(responses[1].result.isError, true);
    assert.equal(responses[2].result.isError, true);
    assert.equal(payload(responses[3]).filesScanned, 1);
    assert.ok(!JSON.stringify(responses).includes(other));
  } finally { rmSync(other, { recursive: true, force: true }); }
}));

test('token-shaped and control-character filenames are sanitized in MCP results', () => sandbox(root => {
  const secret = token();
  writeFileSync(join(root, 'file-' + secret + (process.platform === 'win32' ? '' : '\nspoof') + '.js'), 'const token="' + secret + '";\n');
  const { responses, stdout } = run(root, [
    legacyInit, request(2, 'tools/call', { name: 'safepush_scan', arguments: {} }),
  ]);
  assert.ok(payload(responses[1]).findings.length);
  assert.ok(!stdout.includes(secret));
  assert.ok(!stdout.includes('\nspoof.js'));
  assert.ok(stdout.includes('[REDACTED]'));
}));

test('unknown methods and malformed modern metadata receive JSON-RPC errors', () => sandbox(root => {
  const { responses } = run(root, [
    request(1, 'tools/list'),
    legacyInit,
    request(2, 'unknown/method'),
    request(3, 'tools/list', { _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' } }),
    modernRequest(4, 'tools/call', { name: 'other_tool', arguments: {} }),
    request(5, 'ping'),
  ]);
  assert.equal(responses[0].error.code, -32600);
  assert.equal(responses[2].error.code, -32601);
  assert.equal(responses[3].error.code, -32602);
  assert.equal(responses[4].error.code, -32602);
  assert.deepEqual(responses[5].result, {});
}));

test('startup rejects Git subdirectory to avoid scanning parent unexpectedly', () => sandbox(root => {
  git(['init', '-q'], root);
  mkdirSync(join(root, 'subdir'));
  const p = spawnSync(process.execPath, [executable, '--root', join(root, 'subdir')], {
    encoding: 'utf8', input: '', timeout: 15000,
  });
  assert.equal(p.status, 2);
  assert.equal(p.stdout, '');
  assert.match(p.stderr, /invalid project root/);
}));

test('without --root, a server started in a subdirectory scans the enclosing repository', () => sandbox(root => {
  git(['init', '-q'], root);
  mkdirSync(join(root, 'subdir'));
  writeFileSync(join(root, 'app.js'), 'const t = "' + token() + '";\n');
  const input = [legacyInit, request(2, 'tools/call', { name: 'safepush_scan', arguments: {} })]
    .map(m => JSON.stringify(m)).join('\n') + '\n';
  const p = spawnSync(process.execPath, [executable], {
    cwd: join(root, 'subdir'), encoding: 'utf8', input, timeout: 15000,
  });
  assert.equal(p.status, 0, p.stderr);
  const responses = p.stdout.trim().split('\n').map(line => JSON.parse(line));
  assert.ok(payload(responses[1]).findings.some(f => f.rule === 'KNOWN_SECRET' && f.file === 'app.js'));
  assert.ok(!p.stdout.includes(token()));
}));

test('staged scan failures return an error tool result, not a clean report', () => sandbox(root => {
  git(['init', '-q'], root);
  writeFileSync(join(root, 'oversized.js'), 'x'.repeat(1_000_001));
  git(['add', 'oversized.js'], root);
  const { responses } = run(root, [
    legacyInit, request(2, 'tools/call', { name: 'safepush_scan', arguments: { staged: true } }),
  ]);
  assert.equal(responses[1].result.isError, true);
  assert.match(responses[1].result.content[0].text, /incomplete/);
}));
