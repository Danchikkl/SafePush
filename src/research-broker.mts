#!/usr/bin/env node
/**
 * SafePush research-only broker: synthetic provider, JSON-lines stdio.
 * NO real network calls, real credentials, operating-system isolation or billing.
 * Use a separate OS identity/container for a meaningful agent/broker boundary.
 */
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { isAbsolute, relative, resolve, sep } from 'node:path';

interface Request {
  id: string | number;
  operation: 'mock_complete';
  prompt: string;
  max_output_tokens: number;
}
const INPUT_LIMIT = 512;
const MAX_OUTPUT = 64;
const MAX_CALLS = 10;
const UNIT_PER_INPUT = 2;
const UNIT_PER_OUTPUT = 3;
const MAX_LINE = 4096;
const DEFAULT_BUDGET = 1000; // synthetic accounting units, NOT USD
const keys = new Set(['id', 'operation', 'prompt', 'max_output_tokens']);
const pathWithin = (dir: string, file: string): boolean => {
  const rel = relative(dir, file);
  return rel === '' || (rel !== '..' && !rel.startsWith('..' + sep) && !isAbsolute(rel));
};
function startup(argv: string[]): { fakeKey: string; budget: number } {
  if (argv.length !== 4 || argv[0] !== '--agent-root' || argv[2] !== '--secret-file') throw Error('arguments');
  const agentRoot = realpathSync(resolve(argv[1]));
  const secretPath = realpathSync(resolve(argv[3]));
  if (!lstatSync(agentRoot).isDirectory() || !lstatSync(secretPath).isFile() ||
      pathWithin(agentRoot, secretPath)) throw Error('secret location');
  const key = readFileSync(secretPath, 'utf8').trim();
  if (!/^SAFEPUSH_TEST_KEY_[A-Za-z0-9]{8,32}$/.test(key)) throw Error('use synthetic key only');
  return { fakeKey: key, budget: DEFAULT_BUDGET };
}
function isRequest(x: unknown): x is Request {
  if (!x || typeof x !== 'object' || Array.isArray(x)) return false;
  const obj = x as Record<string, unknown>;
  return Object.keys(obj).every(k => keys.has(k)) &&
    (typeof obj.id === 'string' && obj.id.length > 0 && obj.id.length < 64 ||
      typeof obj.id === 'number' && Number.isSafeInteger(obj.id)) &&
    obj.operation === 'mock_complete' &&
    typeof obj.prompt === 'string' && obj.prompt.length > 0 && obj.prompt.length <= INPUT_LIMIT &&
    Number.isInteger(obj.max_output_tokens) &&
    (obj.max_output_tokens as number) >= 1 && (obj.max_output_tokens as number) <= MAX_OUTPUT;
}
function send(x: Record<string, unknown>): void {
  process.stdout.write(JSON.stringify(x) + '\n');
}
function main(): void {
  let config: ReturnType<typeof startup>;
  try { config = startup(process.argv.slice(2)); }
  catch {
    process.stderr.write('SafePush research broker: invalid startup configuration. Use a synthetic key outside the agent workspace.\n');
    process.exitCode = 2;
    return;
  }
  let available = config.budget;
  let calls = 0;
  const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
  input.on('line', (line: string) => {
    if (Buffer.byteLength(line) > MAX_LINE) {
      send({ ok: false, error: 'request_too_large' });
      return;
    }
    let value: unknown;
    try { value = JSON.parse(line) as unknown; }
    catch { send({ ok: false, error: 'invalid_json' }); return; }
    if (!isRequest(value)) {
      send({ ok: false, error: 'operation_not_allowed_or_bad_arguments' });
      return;
    }
    const { id, prompt, max_output_tokens } = value;
    // Pessimistic reservation BEFORE any simulated provider dispatch.
    const estimatedInput = Math.ceil(Buffer.byteLength(prompt, 'utf8') / 4);
    const reserve = estimatedInput * UNIT_PER_INPUT + max_output_tokens * UNIT_PER_OUTPUT;
    if (calls >= MAX_CALLS || reserve > available) {
      send({ id, ok: false, error: 'budget_or_call_limit_exceeded', remaining_units: available });
      return;
    }
    available -= reserve;
    calls++;
    // Mock provider: verifies broker privately holds a demo credential.
    // Does not connect to any real API, use real tokens, or echo prompt/key.
    if (!config.fakeKey.startsWith('SAFEPUSH_TEST_KEY_')) {
      send({ id, ok: false, error: 'mock_provider_unavailable' });
      return; // reservation not refunded on uncertain provider failure
    }
    const actualOutput = Math.min(8, max_output_tokens);
    const actual = estimatedInput * UNIT_PER_INPUT + actualOutput * UNIT_PER_OUTPUT;
    available += reserve - actual;
    send({
      id, ok: true, result: 'Synthetic provider response; no API request was made.',
      usage: { input_units: estimatedInput, output_units: actualOutput, charged_units: actual },
      remaining_units: available,
    });
  });
}
main();
