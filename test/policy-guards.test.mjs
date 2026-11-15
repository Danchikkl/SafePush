import {test} from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtempSync, realpathSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {loadPolicy} from '../dist/policy.mjs';
import {routeClaudeHook} from '../dist/hook-router.mjs';

const token = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0'.repeat(2);
function sandbox(fn) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'safepush-policy-')));
  try { execFileSync('git', ['init', '-q'], {cwd: dir}); return fn(dir); }
  finally { rmSync(dir, {recursive: true, force: true}); }
}
function route(dir, event) {
  const response = routeClaudeHook({cwd: dir, ...event});
  return response ? JSON.parse(response) : null;
}

test('malformed guard switches retain defaults and cannot silently bypass hook checks', () => sandbox(dir => {
  writeFileSync(join(dir, '.safepush.json'), JSON.stringify({guards: {
    prompt: null, output: 'false', sinks: 0, agentConfig: {}, supplyChain: [], scraping: ''
  }}));
  assert.deepEqual(loadPolicy(dir).guards, {
    prompt: true, output: true, sinks: true, agentConfig: true, supplyChain: true, scraping: true
  });
  const prompt = route(dir, {hook_event_name: 'UserPromptSubmit', prompt: token});
  assert.equal(prompt?.decision, 'block');
  const sink = route(dir, {hook_event_name: 'PreToolUse', tool_name: 'WebFetch',
    tool_input: {url: 'https://example.test/?key=' + token, prompt: 'fetch'}});
  assert.equal(sink?.hookSpecificOutput?.permissionDecision, 'deny');
  const output = route(dir, {hook_event_name: 'PostToolUse', tool_name: 'mcp__demo__read',
    tool_response: {content: [{type: 'text', text: 'token=' + token}]}});
  assert.ok(output?.hookSpecificOutput?.updatedMCPToolOutput);
  assert.ok(!JSON.stringify(output).includes(token));
}));

test('explicit boolean false still disables only the selected guards', () => sandbox(dir => {
  writeFileSync(join(dir, '.safepush.json'), JSON.stringify({guards: {
    prompt: false, sinks: false, output: false, supplyChain: false, scraping: false,
    agentConfig: true, unknownGuard: false
  }}));
  assert.deepEqual(loadPolicy(dir).guards, {
    prompt: false, output: false, sinks: false, agentConfig: true, supplyChain: false, scraping: false
  });
  assert.equal(route(dir, {hook_event_name: 'UserPromptSubmit', prompt: token}), null);
  assert.equal(route(dir, {hook_event_name: 'PostToolUse', tool_name: 'mcp__demo__read',
    tool_response: {content: [{type: 'text', text: token}]}}), null);
}));
