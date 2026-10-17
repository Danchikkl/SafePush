#!/usr/bin/env node
/**
 * SafePush research-only broker: synthetic provider, JSON-lines stdio.
 * NO real network calls, real credentials, operating-system isolation or billing.
 * Use a separate OS identity/container for a meaningful agent/broker boundary.
 */
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { BudgetGovernor, DEFAULT_POLICY, validateRequest } from './research-policy.mjs';

const MAX_LINE = 4096;
const pathWithin = (dir: string, file: string): boolean => {
  const rel = relative(dir, file);
  return rel === '' || (rel !== '..' && !rel.startsWith('..' + sep) && !isAbsolute(rel));
};
function startup(argv: string[]): { fakeKey: string } {
  if (argv.length !== 4 || argv[0] !== '--agent-root' || argv[2] !== '--secret-file') throw Error('arguments');
  const agentRoot = realpathSync(resolve(argv[1]));
  const secretPath = realpathSync(resolve(argv[3]));
  if (!lstatSync(agentRoot).isDirectory() || !lstatSync(secretPath).isFile() ||
      pathWithin(agentRoot, secretPath)) throw Error('secret location');
  const key = readFileSync(secretPath, 'utf8').trim();
  if (!/^SAFEPUSH_TEST_KEY_[A-Za-z0-9]{8,32}$/.test(key)) throw Error('use synthetic key only');
  return { fakeKey: key };
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
  const governor = new BudgetGovernor(DEFAULT_POLICY);
  const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
  input.on('line', (line: string) => {
    if (Buffer.byteLength(line) > MAX_LINE) {
      send({ ok: false, error: 'request_too_large' });
      return;
    }
    let value: unknown;
    try { value = JSON.parse(line) as unknown; }
    catch { send({ ok: false, error: 'invalid_json' }); return; }
    const request = validateRequest(value);
    if (!request) {
      send({ ok: false, error: 'operation_not_allowed_or_bad_arguments' });
      return;
    }
    const { id, prompt, max_output_tokens } = request;
    // Reserve the maximum mock cost BEFORE dispatch and before settlement.
    const reservation = governor.reserve(request);
    if (reservation === null) {
      send({ id, ok: false, error: 'budget_or_call_limit_exceeded', remaining_units: governor.available });
      return;
    }
    // Mock provider: verifies broker privately holds a demo credential.
    // Does not connect to any real API, use real tokens, or echo prompt/key.
    if (!config.fakeKey.startsWith('SAFEPUSH_TEST_KEY_')) {
      governor.forfeit(reservation);
      send({ id, ok: false, error: 'mock_provider_unavailable' });
      return; // reservation not refunded on uncertain provider failure
    }
    const estimatedInput = Math.ceil(Buffer.byteLength(prompt, 'utf8') / 4);
    const actualOutput = Math.min(8, max_output_tokens);
    const actual = estimatedInput * 2 + actualOutput * 3;
    if (!governor.settle(reservation, actual)) {
      governor.forfeit(reservation);
      send({ id, ok: false, error: 'budget_settlement_error' });
      return;
    }
    send({
      id, ok: true, result: 'Synthetic provider response; no API request was made.',
      usage: { input_units: estimatedInput, output_units: actualOutput, charged_units: actual },
      remaining_units: governor.available,
    });
  });
}
main();
