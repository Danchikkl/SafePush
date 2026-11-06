import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BudgetGovernor, validateRequest, maximumCost, DEFAULT_POLICY } from '../dist/research-policy.mjs';

const call = (prompt = 'hello', max_output_tokens = 10) => ({
  id: 1, operation: 'mock_complete', prompt, max_output_tokens,
});

test('capability allowlist denies URLs, alternate operations, unknown keys and invalid types', () => {
  assert.ok(validateRequest(call()));
  for (const request of [
    { ...call(), url: 'https://not-allowed.example' },
    { ...call(), operation: 'fetch_url' },
    { ...call(), max_output_tokens: '10' },
    { ...call(), headers: { Authorization: 'mock-value' } },
    { ...call(), prompt: '' },
    { ...call(), id: {} },
    { ...call(), max_output_tokens: -1 },
    { ...call(), max_output_tokens: 1000 },
    null, [],
  ]) assert.equal(validateRequest(request), null);
});
test('unicode payloads are limited by UTF-8 bytes, not characters', () => {
  assert.equal(validateRequest(call('🛡'.repeat(128)))?.prompt.length, 256);
  assert.equal(validateRequest(call('🛡'.repeat(129))), null);
});
test('reserving concurrent requests never overspends in one process', () => {
  const budget = new BudgetGovernor({ ...DEFAULT_POLICY, budgetUnits: 400, maxCalls: 10 });
  const request = call('A'.repeat(200), 50); // max 100 + 150 = 250 units
  const a = budget.reserve(request);
  const b = budget.reserve(request);
  assert.ok(a !== null);
  assert.equal(b, null);
  assert.equal(budget.available, 150);
  assert.equal(budget.outstanding, 250);
  assert.equal(budget.settle(a, 150), true);
  assert.equal(budget.available, 250);
  const c = budget.reserve(request);
  assert.ok(c !== null);
  assert.equal(budget.available, 0);
  assert.equal(budget.outstanding, 250);
});
test('invalid settlement cannot mint extra budget or double refund', () => {
  const budget = new BudgetGovernor();
  const id = budget.reserve(call());
  assert.ok(id !== null);
  assert.equal(budget.settle(id, -1), false);
  assert.equal(budget.settle(id, maximumCost(call()) + 1), false);
  assert.equal(budget.settle(id, 0.5), false);
  assert.equal(budget.outstanding, maximumCost(call()));
  assert.equal(budget.settle(id, 7), true);
  assert.equal(budget.settle(id, 0), false);
  assert.equal(budget.available, 1000 - 7);
});
test('uncertain provider outcome forfeits reservation without crediting budget', () => {
  const budget = new BudgetGovernor();
  const id = budget.reserve(call());
  assert.ok(id !== null);
  const after = budget.available;
  assert.equal(budget.forfeit(id), true);
  assert.equal(budget.available, after);
  assert.equal(budget.forfeit(id), false);
  assert.equal(budget.outstanding, 0);
});
test('cannot bypass call cap by settling cheaply', () => {
  const budget = new BudgetGovernor({ ...DEFAULT_POLICY, maxCalls: 2 });
  for (let i = 0; i < 2; i++) {
    const id = budget.reserve(call());
    assert.ok(id !== null);
    assert.equal(budget.settle(id, 0), true);
  }
  assert.equal(budget.reserve(call()), null);
  assert.equal(budget.available, 1000);
});
