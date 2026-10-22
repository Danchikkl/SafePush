import type { Finding, RuleId } from './types.mjs';
import { basename } from 'node:path';

interface KnownPattern {
  provider: string;
  pattern: RegExp;
  /** Formats that are often intentionally public in browser code are reported as medium. */
  severity?: 'high' | 'medium';
}
const patterns: KnownPattern[] = [
  { provider: 'GitHub access token', pattern: /\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{30,}\b/g },
  { provider: 'GitHub fine-grained token', pattern: /\bgithub_pat_[A-Za-z0-9_]{30,}\b/g },
  { provider: 'Anthropic API key', pattern: /\bsk-ant-[A-Za-z0-9]+-[A-Za-z0-9_-]{20,}/g },
  { provider: 'OpenAI-style API key', pattern: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { provider: 'Stripe secret key', pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b/g },
  { provider: 'Stripe restricted key', pattern: /\brk_(?:live|test)_[A-Za-z0-9]{20,}\b/g },
  { provider: 'Slack token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{18,}\b/g },
  { provider: 'AWS access key ID', pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { provider: 'private key block', pattern: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g },
  { provider: 'Google API key (may be intentionally public, e.g. Firebase web config)', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: 'medium' },
];
// user:password@ inside a connection URL. The password group is checked against placeholders separately.
const credentialUrl = /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver):\/\/[^\s:@\/'"`]+:([^\s@\/'"`]+)@/gi;
const defaultUrlPasswords = /^(?:postgres|password|passwd|root|admin|secret|example|changeme|pass|test|guest|mysql|redis)$/i;
export function redactKnownSecrets(text: string): string {
  let value = text;
  for (const { pattern } of patterns) {
    pattern.lastIndex = 0;
    value = value.replace(pattern, '[REDACTED]');
  }
  credentialUrl.lastIndex = 0;
  return value.replace(credentialUrl, match => match.slice(0, match.indexOf('://') + 3) + '[REDACTED]@');
}
const likelySecretName = /(?:API[_-]?KEY|PRIVATE[_-]?KEY|SECRET|PASSWORD|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN)/i;
const publicEnvName = /^(?:NEXT_PUBLIC_|VITE_|REACT_APP_)/;
// Identifier containing a sensitive word (OPENAI_API_KEY, apiKey, "client_secret", DB_PASSWORD),
// optionally quoted (JSON/YAML keys), assigned a quoted literal.
const genericAssignment = /(?<![A-Za-z0-9])([A-Za-z0-9_.-]*(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|private[_-]?key|password|passwd)[A-Za-z0-9_]*)['"]?\s*(?:[:=]|:=|=>)\s*['"]([^'"\s]{16,})['"]/gi;
// Extra names that are dangerous behind NEXT_PUBLIC_/VITE_/REACT_APP_ even without KEY/SECRET wording.
const sensitivePublicName = /(?:SERVICE[_-]?ROLE|DATABASE[_-]?URL|DB[_-]?(?:URL|PASS)|CONNECTION[_-]?STRING|SIGNING[_-]?KEY|ENCRYPTION[_-]?KEY|ADMIN[_-]?KEY)/i;
function isSensitivePublicName(name: string): boolean {
  return likelySecretName.test(name) || sensitivePublicName.test(name);
}
const envVarAssignment = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.+?)\s*$/;
const placeholder = /^(?:example|placeholder|dummy|changeme|replace[_-]?me|your[_-]?|test[_-]?key|xxx|<|\$\{|\{\{|\$[A-Z_]|process\.env|import\.meta)/i;

export function isEnvFile(path: string): boolean {
  const name = basename(path);
  return name === '.env' || name.startsWith('.env.');
}
export function isEnvTemplate(path: string): boolean {
  return /(?:\.example|\.sample|\.template)$/i.test(basename(path));
}
export function finding(rule: RuleId, severity: 'high' | 'medium', file: string, line: number | undefined, title: string, why: string, fix: string): Finding {
  return { rule, severity, file, ...(line === undefined ? {} : { line }), title, why, fix };
}
function deduplicate(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = f.rule + ':' + f.file + ':' + (f.line ?? 0);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
export function scanContent(path: string, text: string): Finding[] {
  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    const lineNo = index + 1;
    let knownSecretOnLine = false;
    for (const { provider, pattern, severity = 'high' } of patterns) {
      pattern.lastIndex = 0;
      if (pattern.test(line)) {
        knownSecretOnLine = true;
        findings.push(finding('KNOWN_SECRET', severity, path, lineNo,
          'Possible ' + provider,
          'A value resembling a credential is present in source code. SafePush does not test whether it works.',
          'If real, revoke/rotate it at the provider. Remove it from code; if committed, consider the Git history exposed. Use server-side environment variables.'));
      }
    }
    const publicNames = new Set<string>();
    const referenceRegex = /\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z][A-Z0-9_]*\b/g;
    for (const match of line.matchAll(referenceRegex)) {
      if (isSensitivePublicName(match[0])) publicNames.add(match[0]);
    }
    const envAssignment = isEnvFile(path) ? envVarAssignment.exec(line) : null;
    if (envAssignment && publicEnvName.test(envAssignment[1]) && isSensitivePublicName(envAssignment[1])) {
      publicNames.add(envAssignment[1]);
    }
    if (publicNames.size) {
      findings.push(finding('CLIENT_EXPOSED_SECRET_NAME', 'medium', path, lineNo,
        'Potentially sensitive browser-exposed environment variable',
        'NEXT_PUBLIC_, VITE_, and REACT_APP_ variables can be included in client-side bundles. Names alone are not proof of a leak.',
        'If confidential, move access to server-side code. Public identifiers may be safe; verify provider guidance.'));
    }
    if (!knownSecretOnLine) {
      genericAssignment.lastIndex = 0;
      const generic = [...line.matchAll(genericAssignment)].find(m => !placeholder.test(m[2]) && new Set(m[2]).size >= 8);
      if (generic) {
        findings.push(finding('GENERIC_SECRET_ASSIGNMENT', 'medium', path, lineNo,
          'Suspicious hardcoded credential assignment',
          'A sensitive variable contains a long literal. This heuristic can produce false positives.',
          'If real, revoke it and replace it with a server-side secret.'));
      }
      credentialUrl.lastIndex = 0;
      const urlPassword = [...line.matchAll(credentialUrl)].map(m => m[1]).find(pw =>
        pw.length >= 6 && !defaultUrlPasswords.test(pw) && !placeholder.test(pw) && !pw.includes('$') && !/^[*x.]+$/i.test(pw));
      if (urlPassword) {
        findings.push(finding('GENERIC_SECRET_ASSIGNMENT', 'medium', path, lineNo,
          'Possible password inside a connection URL',
          'A database or queue URL appears to contain an inline password. SafePush never prints it.',
          'If real, rotate the password and load the URL from a server-side environment variable.'));
      }
      if (envAssignment && likelySecretName.test(envAssignment[1])) {
        const value = envAssignment[2].replace(/^['"]|['"]$/g, '').trim();
        if (value.length >= 16 && !placeholder.test(value) && new Set(value).size >= 8) {
          findings.push(finding('GENERIC_SECRET_ASSIGNMENT', 'medium', path, lineNo,
            'Possible credential in environment file',
            'A sensitive-looking variable has a non-placeholder value. SafePush never prints it.',
            'Do not commit real environment files; rotate the credential if exposed.'));
        }
      }
    }
  }
  return deduplicate(findings);
}
export function envIgnoreMissing(contents: string): boolean {
  let envIgnored = false;
  let variantsIgnored = false;
  for (const line of contents.split(/\r?\n/).map(x => x.trim())) {
    if (!line || line.startsWith('#')) continue;
    const negated = line.startsWith('!');
    const rule = negated ? line.slice(1) : line;
    if (rule === '.env*' || rule === '**/.env*') {
      envIgnored = !negated;
      variantsIgnored = !negated;
    } else if (rule === '.env' || rule === '**/.env') envIgnored = !negated;
    else if (rule === '.env.*' || rule === '**/.env.*') variantsIgnored = !negated;
  }
  return !envIgnored || !variantsIgnored;
}
