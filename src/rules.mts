import type { Finding, RuleId } from './types.mjs';
import { basename } from 'node:path';

const patterns = [
  { provider: 'GitHub access token', pattern: /\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{30,}\b/g },
  { provider: 'GitHub fine-grained token', pattern: /\bgithub_pat_[A-Za-z0-9_]{30,}\b/g },
  { provider: 'OpenAI-style API key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { provider: 'Stripe secret key', pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b/g },
  { provider: 'Slack token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{18,}\b/g },
];
export function redactKnownSecrets(text: string): string {
  let value = text;
  for (const { pattern } of patterns) {
    pattern.lastIndex = 0;
    value = value.replace(pattern, '[REDACTED]');
  }
  return value;
}
const likelySecretName = /(?:API[_-]?KEY|PRIVATE[_-]?KEY|SECRET|PASSWORD|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN)/i;
const publicEnvName = /^(?:NEXT_PUBLIC_|VITE_|REACT_APP_)/;
const genericAssignment = /\b(api[_-]?key|secret|access[_-]?token|private[_-]?key|password)\b\s*[:=]\s*['"]([^'"\s]{16,})['"]/gi;
const envVarAssignment = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.+?)\s*$/;
const placeholder = /^(?:example|placeholder|dummy|changeme|replace[_-]?me|your[_-]?|test[_-]?key|xxx|<|\$\{|\{\{)/i;

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
    for (const { provider, pattern } of patterns) {
      pattern.lastIndex = 0;
      if (pattern.test(line)) {
        knownSecretOnLine = true;
        findings.push(finding('KNOWN_SECRET', 'high', path, lineNo,
          'Possible ' + provider,
          'A value resembling a credential is present in source code. SafePush does not test whether it works.',
          'If real, revoke/rotate it at the provider. Remove it from code; if committed, consider the Git history exposed. Use server-side environment variables.'));
      }
    }
    const publicNames = new Set<string>();
    const referenceRegex = /\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z][A-Z0-9_]*\b/g;
    for (const match of line.matchAll(referenceRegex)) {
      if (likelySecretName.test(match[0])) publicNames.add(match[0]);
    }
    const envAssignment = isEnvFile(path) ? envVarAssignment.exec(line) : null;
    if (envAssignment && publicEnvName.test(envAssignment[1]) && likelySecretName.test(envAssignment[1])) {
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
      const generic = genericAssignment.exec(line);
      if (generic && !placeholder.test(generic[2]) && new Set(generic[2]).size >= 8) {
        findings.push(finding('GENERIC_SECRET_ASSIGNMENT', 'medium', path, lineNo,
          'Suspicious hardcoded credential assignment',
          'A sensitive variable contains a long literal. This heuristic can produce false positives.',
          'If real, revoke it and replace it with a server-side secret.'));
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
