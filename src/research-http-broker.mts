#!/usr/bin/env node
/**
 * Synthetic-only HTTP broker for isolated-container research.
 *
 * NOT a hosted product, TLS endpoint, trusted network boundary, or real provider.
 * Do not deploy on an untrusted network or use live keys.
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { resolve } from 'node:path';
import { BudgetGovernor, DEFAULT_POLICY, validateRequest } from './research-policy.mjs';

const MAX_REQUEST_BYTES = 4096;
const RESPONSE = 'Synthetic provider response; no API request was made.';

function readFixture(filename: string, pattern: RegExp): string {
  const path = resolve(filename);
  if (!lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) throw Error('invalid fixture path');
  const actual = realpathSync(path);
  if (actual !== path && process.platform !== 'win32') throw Error('indirect fixture path');
  const value = readFileSync(actual, 'utf8').trim();
  if (!pattern.test(value)) throw Error('synthetic fixture required');
  return value;
}

function options(argv: string[]): { host: string; port: number; mockKey: string; capability: string } {
  const pairs = new Map<string, string>();
  if (argv.length % 2 !== 0) throw Error('missing option');
  for (let i = 0; i < argv.length; i += 2) {
    if (!['--host','--port','--secret-file','--capability-file'].includes(argv[i]) || pairs.has(argv[i]))
      throw Error('invalid option');
    pairs.set(argv[i], argv[i + 1]);
  }
  if (pairs.size !== 4) throw Error('missing options');
  const host = pairs.get('--host')!;
  // Docker use is explicitly opt-in; still NOT proof this process is containerized.
  if (host !== '127.0.0.1' &&
      !(host === '0.0.0.0' && process.env.SAFEPUSH_RESEARCH_CONTAINER_ONLY === '1'))
    throw Error('non-loopback listening needs explicit research opt-in');
  const raw = pairs.get('--port')!;
  const port = Number(raw);
  if (!/^\d{1,5}$/.test(raw) || !Number.isSafeInteger(port) || port < 0 || port > 65535)
    throw Error('invalid port');
  const secretFile = resolve(pairs.get('--secret-file')!);
  const capabilityFile = resolve(pairs.get('--capability-file')!);
  if (secretFile === capabilityFile) throw Error('separate capability and provider secret');
  const mockKey = readFixture(secretFile, /^SAFEPUSH_TEST_KEY_[A-Za-z0-9]{8,32}$/);
  const capability = readFixture(capabilityFile, /^SAFEPUSH_CAP_[A-Za-z0-9]{24,64}$/);
  return { host, port, mockKey, capability };
}

function hasCapability(received: string | undefined, expected: string): boolean {
  const provided = received?.startsWith('Bearer ') ? received.slice(7) : '';
  // Hash both strings to fixed-size buffers before constant-time comparison.
  const a = createHash('sha256').update(provided).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b) && provided.length === expected.length;
}

function respond(res: ServerResponse, status: number, body: Record<string, unknown>): void {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(JSON.stringify(body));
}

function main(): void {
  let config: ReturnType<typeof options>;
  try { config = options(process.argv.slice(2)); }
  catch {
    process.stderr.write('SafePush research HTTP broker: invalid synthetic configuration.\n');
    process.exitCode = 2;
    return;
  }
  const governor = new BudgetGovernor(DEFAULT_POLICY);
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    // Authentication must precede action dispatch; errors never echo input or credentials.
    if (!hasCapability(req.headers.authorization, config.capability)) {
      respond(res, 401, { ok: false, error: 'unauthorized' });
      req.resume();
      return;
    }
    if (req.method !== 'POST' || req.url !== '/v1/mock-complete') {
      respond(res, 404, { ok: false, error: 'operation_not_allowed' });
      req.resume();
      return;
    }
    if ((req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() !== 'application/json') {
      respond(res, 415, { ok: false, error: 'json_required' });
      req.resume();
      return;
    }
    const announced = Number(req.headers['content-length'] ?? 0);
    if (!Number.isFinite(announced) || announced > MAX_REQUEST_BYTES) {
      respond(res, 413, { ok: false, error: 'request_too_large' });
      req.resume();
      return;
    }
    let size = 0;
    const chunks: Buffer[] = [];
    let rejected = false;
    req.on('data', (chunk: Buffer) => {
      if (rejected) return;
      size += chunk.length;
      if (size > MAX_REQUEST_BYTES) {
        rejected = true;
        respond(res, 413, { ok: false, error: 'request_too_large' });
        req.pause();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (rejected || res.writableEnded) return;
      let body: unknown;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown; }
      catch { respond(res, 400, { ok: false, error: 'invalid_json' }); return; }
      const call = validateRequest(body);
      if (!call) {
        respond(res, 400, { ok: false, error: 'operation_not_allowed_or_bad_arguments' });
        return;
      }
      const reservation = governor.reserve(call);
      if (reservation === null) {
        respond(res, 429, { id: call.id, ok: false, error: 'budget_or_call_limit_exceeded' });
        return;
      }
      // The synthetic provider is a fixed local operation, NOT a network proxy.
      const syntheticInputUnits = Math.ceil(Buffer.byteLength(call.prompt, 'utf8') / 4);
      const outputUnits = Math.min(8, call.max_output_tokens);
      const charged = syntheticInputUnits * 2 + outputUnits * 3;
      if (!governor.settle(reservation, charged)) {
        governor.forfeit(reservation);
        respond(res, 500, { ok: false, error: 'settlement_failed' });
        return;
      }
      respond(res, 200, {
        id: call.id, ok: true, result: RESPONSE,
        usage: { input_units: syntheticInputUnits, output_units: outputUnits, charged_units: charged },
        remaining_units: governor.available,
      });
    });
    req.on('error', () => {
      if (!res.writableEnded && !res.destroyed) respond(res, 400, { ok: false, error: 'invalid_request' });
    });
  });
  server.maxHeadersCount = 16;
  server.headersTimeout = 10_000;
  server.requestTimeout = 10_000;
  server.timeout = 10_000;
  server.listen(config.port, config.host, () => {
    const address = server.address();
    if (address && typeof address !== 'string') process.stdout.write('READY ' + address.port + '\n');
  });
  server.on('error', () => {
    process.stderr.write('SafePush research HTTP broker: failed to listen.\n');
    process.exitCode = 2;
  });
}
main();
