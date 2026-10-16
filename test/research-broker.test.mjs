import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const exe = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'research-broker.mjs');
const DEMO_KEY = 'SAFEPUSH_TEST_KEY_SYNTHETIC1234567890';
function fixture(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'safepush-broker-'));
  const agent = join(dir, 'agent');
  const key = join(dir, 'broker-only-demo-secret.txt');
  mkdirSync(agent);
  writeFileSync(key, DEMO_KEY);
  try { fn({ agent, key, dir }); } finally { rmSync(dir, { recursive: true, force: true }); }
}
function request(id = 1, prompt = 'hello', max_output_tokens = 5) {
  return { id, operation: 'mock_complete', prompt, max_output_tokens };
}
function run(agent, key, payloads) {
  const input = payloads.map(x => typeof x === 'string' ? x : JSON.stringify(x)).join('\n') + '\n';
  const r = spawnSync(process.execPath, [exe, '--agent-root', agent, '--secret-file', key], {
    input, encoding: 'utf8', timeout: 10000,
  });
  return { ...r, responses: r.stdout.trim().split('\n').filter(Boolean).map(x => JSON.parse(x)) };
}
test('broker makes a synthetic request, never returns the key or prompt', () => fixture(({ agent, key }) => {
  const p = 'Private prompt: not for output';
  const r = run(agent, key, [request(7, p)]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.responses[0].ok, true);
  assert.equal(r.responses[0].id, 7);
  assert.ok(!r.stdout.includes(DEMO_KEY));
  assert.ok(!r.stdout.includes(p));
  assert.ok(r.responses[0].remaining_units < 1000);
}));
test('rejects raw API passthrough, unrelated operations and unknown fields', () => fixture(({ agent, key }) => {
  const r = run(agent, key, [
    { ...request(), url: 'https://example.invalid/collect' },
    { ...request(), operation: 'fetch_any_url' },
    { ...request(), max_output_tokens: 9000 },
    { ...request(), prompt: '' },
  ]);
  assert.equal(r.status, 0, r.stderr);
  assert.ok(r.responses.every(x => x.ok === false));
  assert.ok(r.responses.every(x => x.error === 'operation_not_allowed_or_bad_arguments'));
}));
test('fails closed when reserving the maximum cost exceeds available units', () => fixture(({ agent, key }) => {
  const payload = 'x'.repeat(512);
  const r = run(agent, key, [request(1, payload, 64), request(2, payload, 64), request(3, payload, 64)]);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.responses.map(x => x.ok), [true, true, false]);
  assert.equal(r.responses[2].error, 'budget_or_call_limit_exceeded');
}));
test('enforces maximum allowed call count', () => fixture(({ agent, key }) => {
  const r = run(agent, key, Array.from({ length: 11 }, (_, i) => request(i, 'x', 1)));
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.responses.filter(x => x.ok).length, 10);
  assert.equal(r.responses[10].error, 'budget_or_call_limit_exceeded');
}));
test('rejects secret file inside agent root or real provider key', () => fixture(({ agent, key }) => {
  const exposed = join(agent, 'secret.txt');
  writeFileSync(exposed, DEMO_KEY);
  const unsafe = run(agent, exposed, [request()]);
  assert.equal(unsafe.status, 2);
  assert.equal(unsafe.responses.length, 0);
  assert.ok(!unsafe.stderr.includes(DEMO_KEY));
  writeFileSync(key, 'sk-real-looking-provider-key');
  const bad = run(agent, key, [request()]);
  assert.equal(bad.status, 2);
  assert.equal(bad.responses.length, 0);
}));
test('malformed JSON and oversized requests are rejected without echo', () => fixture(({ agent, key }) => {
  const r = run(agent, key, ['{private-not-to-echo', 'x'.repeat(4200)]);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.responses.map(x => x.error), ['invalid_json', 'request_too_large']);
  assert.ok(!r.stdout.includes('private-not-to-echo'));
}));
