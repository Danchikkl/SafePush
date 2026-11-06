import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const exe = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'research-http-broker.mjs');
const MOCK_KEY = 'SAFEPUSH_TEST_KEY_SYNTHETIC1234567890';
const CAP = 'SAFEPUSH_CAP_SYNTHETICSCOPEDCAPABILITY1234567890';
const BASE_REQUEST = { id: 1, operation: 'mock_complete', prompt: 'Safe synthetic text', max_output_tokens: 8 };

async function runServer(t, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'safepush-http-demo-'));
  const secret = join(dir, 'mock_key.txt');
  const capability = join(dir, 'capability.txt');
  writeFileSync(secret, MOCK_KEY);
  writeFileSync(capability, CAP);
  const child = spawn(process.execPath, [
    exe, '--host', '127.0.0.1', '--port', '0',
    '--secret-file', secret, '--capability-file', capability,
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', chunk => { stderr += chunk; });
  try {
    const port = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(Error('Broker did not start')), 10000);
      let buffer = '';
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', chunk => {
        buffer += chunk;
        const m = /READY (\d+)\n/.exec(buffer);
        if (m) { clearTimeout(timer); resolve(Number(m[1])); }
      });
      child.once('error', err => { clearTimeout(timer); reject(err); });
      child.once('exit', () => { clearTimeout(timer); reject(Error('Broker exited early')); });
    });
    const origin = 'http://127.0.0.1:' + port;
    const post = async (body, token = CAP, path = '/v1/mock-complete') => {
      const res = await fetch(origin + path, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: 'Bearer ' + token },
        body: typeof body === 'string' ? body : JSON.stringify(body),
        signal: AbortSignal.timeout(3000),
      });
      return { status: res.status, body: await res.json() };
    };
    await fn({ post, origin });
  } finally {
    child.kill();
    rmSync(dir, { recursive: true, force: true });
  }
  assert.ok(!stderr.includes(MOCK_KEY));
  assert.ok(!stderr.includes(CAP));
}

test('HTTP broker rejects unauthenticated calls before dispatch and reveals no provider key', async t => {
  await runServer(t, async ({ post, origin }) => {
    const invalid = await post(BASE_REQUEST, 'SAFEPUSH_CAP_WRONGWRONGWRONGWRONGWRONGWRONGWRONG');
    assert.equal(invalid.status, 401);
    assert.equal(invalid.body.error, 'unauthorized');
    const missing = await fetch(origin + '/v1/mock-complete', {
      method: 'POST', body: '{}', headers: { 'content-type': 'application/json' },
    });
    assert.equal(missing.status, 401);
    const allowed = await post(BASE_REQUEST);
    assert.equal(allowed.status, 200);
    assert.equal(allowed.body.ok, true);
    assert.ok(!JSON.stringify(allowed.body).includes(MOCK_KEY));
    assert.ok(!JSON.stringify(allowed.body).includes(CAP));
    assert.ok(!JSON.stringify(allowed.body).includes(BASE_REQUEST.prompt));
  });
});
test('HTTP broker denies arbitrary endpoint / tool and malformed or oversized payload', async t => {
  await runServer(t, async ({ post }) => {
    assert.equal((await post(BASE_REQUEST, CAP, '/v1/fetch-url')).status, 404);
    assert.equal((await post({ ...BASE_REQUEST, operation: 'fetch_url' })).status, 400);
    assert.equal((await post({ ...BASE_REQUEST, url: 'http://169.254.169.254/latest/meta-data/' })).status, 400);
    assert.equal((await post('{invalid-json')).status, 400);
    assert.equal((await post('x'.repeat(5000))).status, 413);
  });
});
test('budget is shared across authenticated calls inside one broker process', async t => {
  await runServer(t, async ({ post }) => {
    const results = await Promise.all(Array.from({ length: 12 }, (_, i) => post({ ...BASE_REQUEST, id: i })));
    assert.equal(results.filter(r => r.status === 200).length, 10);
    assert.equal(results.filter(r => r.status === 429).length, 2);
    assert.ok(results.every(r => [200, 429].includes(r.status)));
  });
});
test('synthetic broker has no DNS/API passthrough option', async t => {
  await runServer(t, async ({ post }) => {
    const values = [
      { ...BASE_REQUEST, headers: { Authorization: 'anything' } },
      { ...BASE_REQUEST, method: 'GET' },
      { ...BASE_REQUEST, model: 'not-allowed' },
    ];
    for (const v of values) assert.equal((await post(v)).status, 400);
    assert.equal((await post(BASE_REQUEST)).status, 200);
  });
});
