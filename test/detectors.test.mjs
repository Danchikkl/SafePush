import {test} from 'node:test';
import assert from 'node:assert/strict';
import {scanContent, redactKnownSecrets} from '../dist/rules.mjs';

// Synthetic values only. Every credential-shaped string is assembled at runtime so this
// file itself never contains a literal that looks like a real credential.
const j = (...parts) => parts.join('');
const body = (n) => 'Zx81Qw92Er73Ty64Ui55Op46As37Df28Gh19Jk'.repeat(2).slice(0, n);
const fake = {
  github: j('gh', 'p_', body(36)),
  anthropic: j('sk', '-ant-', 'api03-', body(32)),
  openai: j('sk', '-proj-', body(32)),
  stripeRestricted: j('rk', '_live_', body(24)),
  aws: j('AK', 'IA', 'Z7QXJ4MBN3KD8PLE'),
  google: j('AI', 'za', body(35)),
  pem: j('-----BEGIN ', 'RSA ', 'PRIVATE KEY-----'),
  pemOpenssh: j('-----BEGIN ', 'OPENSSH ', 'PRIVATE KEY-----'),
  dbUrl: j('postgres', '://admin:', 'S3cr3tPassw0rd99', '@db.example.test:5432/app'),
  literal: body(24),
};
const rules = (path, text) => scanContent(path, text).map(f => f.rule + ':' + f.severity);
const titles = (path, text) => scanContent(path, text).map(f => f.title);

// --- Positive cases: things AI coding agents commonly generate ---
const positives = [
  ['SCREAMING_CASE constant', 'src/ai.ts', `const OPENAI_API_KEY = "${fake.literal}";`, 'GENERIC_SECRET_ASSIGNMENT:medium'],
  ['camelCase object key', 'src/cfg.ts', `export default { apiKey: '${fake.literal}' };`, 'GENERIC_SECRET_ASSIGNMENT:medium'],
  ['JSON key', 'config.json', `  "client_secret": "${fake.literal}",`, 'GENERIC_SECRET_ASSIGNMENT:medium'],
  ['Python kwarg', 'app.py', `client = Client(api_key="${fake.literal}")`, 'GENERIC_SECRET_ASSIGNMENT:medium'],
  ['DB_PASSWORD', 'settings.py', `DB_PASSWORD = '${fake.literal}'`, 'GENERIC_SECRET_ASSIGNMENT:medium'],
  ['GitHub token', 'a.js', `const t = "${fake.github}";`, 'KNOWN_SECRET:high'],
  ['Anthropic key', 'a.js', `const k = "${fake.anthropic}";`, 'KNOWN_SECRET:high'],
  ['OpenAI project key', 'a.js', `const k = "${fake.openai}";`, 'KNOWN_SECRET:high'],
  ['Stripe restricted key', 'a.js', `stripe("${fake.stripeRestricted}")`, 'KNOWN_SECRET:high'],
  ['AWS access key id', 'a.js', `const id = "${fake.aws}";`, 'KNOWN_SECRET:high'],
  ['RSA private key block', 'key.pem', fake.pem, 'KNOWN_SECRET:high'],
  ['OpenSSH private key block', 'id_ed25519', fake.pemOpenssh, 'KNOWN_SECRET:high'],
  ['Google API key is medium', 'a.js', `const g = "${fake.google}";`, 'KNOWN_SECRET:medium'],
  ['password inside DB URL', 'db.ts', `const url = "${fake.dbUrl}";`, 'GENERIC_SECRET_ASSIGNMENT:medium'],
  ['public Supabase service role', 'page.tsx', 'createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)', 'CLIENT_EXPOSED_SECRET_NAME:medium'],
  ['public DATABASE_URL', 'page.tsx', 'fetch(process.env.NEXT_PUBLIC_DATABASE_URL)', 'CLIENT_EXPOSED_SECRET_NAME:medium'],
  ['public DATABASE_URL in .env', '.env.local', 'VITE_DATABASE_URL=postgres://localhost/app', 'CLIENT_EXPOSED_SECRET_NAME:medium'],
];
for (const [name, path, text, expected] of positives) {
  test('detects: ' + name, () => assert.ok(rules(path, text).includes(expected), JSON.stringify(rules(path, text))));
}

test('Anthropic keys are not labelled as OpenAI-style', () => {
  const t = titles('a.js', `"${fake.anthropic}"`);
  assert.ok(t.some(x => x.includes('Anthropic')));
  assert.ok(!t.some(x => x.includes('OpenAI')));
});

// --- Negative cases: common code that must stay quiet ---
const negatives = [
  ['env reference', 'src/ai.ts', 'const OPENAI_API_KEY = process.env.OPENAI_API_KEY;'],
  ['short value', 'a.ts', 'const apiKey = "abc";'],
  ['placeholder', '.env.example', 'OPENAI_API_KEY=your_openai_key_here'],
  ['template placeholder', 'a.ts', 'const secret = "${process.env.SECRET_VALUE}";'],
  ['shell variable', 'deploy.yml', 'password: "$DEPLOY_PASSWORD_FROM_CI"'],
  ['low-variety value', 'a.ts', 'const password = "aaaaaaaaaaaaaaaaaaaaaaaa";'],
  ['form field label', 'form.tsx', '<input name="password" placeholder="Enter your password" />'],
  ['secret-ish identifier without literal', 'a.ts', 'function getSecretManagerClient(region: string) {}'],
  ['public key block', 'key.pub', j('-----BEGIN ', 'PUBLIC KEY-----')],
  ['default docker password in URL', 'compose.yml', 'DATABASE_URL: postgres://postgres:postgres@db:5432/app'],
  ['env-var password in URL', 'a.ts', 'const url = `postgres://app:${process.env.PGPASSWORD}@db/app`;'],
  ['publishable Stripe key public name', 'page.tsx', 'process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY'],
  ['Supabase anon key public name', 'page.tsx', 'process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY'],
  ['public site URL', 'page.tsx', 'process.env.NEXT_PUBLIC_SITE_URL'],
];
for (const [name, path, text] of negatives) {
  test('ignores: ' + name, () => assert.deepEqual(rules(path, text), []));
}

test('redaction removes new credential formats and URL passwords', () => {
  const text = [fake.aws, fake.anthropic, fake.stripeRestricted, fake.dbUrl].join(' ');
  const redacted = redactKnownSecrets(text);
  for (const v of [fake.aws, fake.anthropic, fake.stripeRestricted, 'S3cr3tPassw0rd99']) assert.ok(!redacted.includes(v), v);
});

test('findings never contain the matched value', () => {
  for (const [, path, text] of positives) {
    const out = JSON.stringify(scanContent(path, text));
    for (const v of Object.values(fake)) assert.ok(!out.includes(v));
  }
});
