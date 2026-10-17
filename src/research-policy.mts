/**
 * Research-only policy core. All operations are explicit capabilities.
 * Cost units are synthetic; this does NOT bound real provider billing.
 */
export type Operation = 'mock_complete';
export interface AuthorizedCall {
  id: string | number;
  operation: Operation;
  prompt: string;
  max_output_tokens: number;
}
export interface BudgetPolicy {
  budgetUnits: number;
  maxCalls: number;
  maxInputBytes: number;
  maxOutputTokens: number;
}
export const DEFAULT_POLICY: Readonly<BudgetPolicy> = Object.freeze({
  budgetUnits: 1000,
  maxCalls: 10,
  maxInputBytes: 512,
  maxOutputTokens: 64,
});
const allowedFields = new Set(['id', 'operation', 'prompt', 'max_output_tokens']);
export function validateRequest(input: unknown, policy: BudgetPolicy = DEFAULT_POLICY): AuthorizedCall | null {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) return null;
  const x = input as Record<string, unknown>;
  if (Object.keys(x).some(k => !allowedFields.has(k))) return null;
  if (!((typeof x.id === 'string' && x.id.length > 0 && x.id.length < 64) ||
    (typeof x.id === 'number' && Number.isSafeInteger(x.id)))) return null;
  if (x.operation !== 'mock_complete' || typeof x.prompt !== 'string' ||
    !x.prompt.length || Buffer.byteLength(x.prompt, 'utf8') > policy.maxInputBytes) return null;
  if (typeof x.max_output_tokens !== 'number' || !Number.isSafeInteger(x.max_output_tokens) ||
      x.max_output_tokens < 1 || x.max_output_tokens > policy.maxOutputTokens) return null;
  return x as unknown as AuthorizedCall;
}
export function maximumCost(call: AuthorizedCall): number {
  // Deliberately pessimistic *mock* estimate, not an actual tokenizer.
  return Buffer.byteLength(call.prompt, 'utf8') * 2 + call.max_output_tokens * 3;
}
export class BudgetGovernor {
  private remaining: number;
  private calls = 0;
  private held = new Map<number, number>();
  private next = 0;
  constructor(private readonly policy: BudgetPolicy = DEFAULT_POLICY) {
    if (!Number.isSafeInteger(policy.budgetUnits) || policy.budgetUnits < 0 ||
        !Number.isSafeInteger(policy.maxCalls) || policy.maxCalls < 0) throw Error('invalid budget');
    this.remaining = policy.budgetUnits;
  }
  // Synchronous reserve is atomic within this one JS process/event-loop only.
  // No multi-process or persistent guarantees; do not use with billable calls.
  reserve(call: AuthorizedCall): number | null {
    const amount = maximumCost(call);
    if (!Number.isSafeInteger(amount) || this.calls >= this.policy.maxCalls ||
        amount > this.remaining) return null;
    this.remaining -= amount;
    this.calls++;
    const id = ++this.next;
    this.held.set(id, amount);
    return id;
  }
  settle(id: number, charged: number): boolean {
    const reserved = this.held.get(id);
    if (reserved === undefined || !Number.isSafeInteger(charged) || charged < 0 ||
        charged > reserved) return false;
    this.held.delete(id);
    this.remaining += reserved - charged;
    return true;
  }
  // An uncertain provider outcome is charged the full reserved amount.
  forfeit(id: number): boolean {
    if (!this.held.has(id)) return false;
    this.held.delete(id);
    return true;
  }
  get available(): number { return this.remaining; }
  get totalCalls(): number { return this.calls; }
  get outstanding(): number { return [...this.held.values()].reduce((a,b) => a+b,0); }
}
