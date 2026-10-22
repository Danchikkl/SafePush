/**
 * Project policy and suppressions.
 *
 * A guardrail that blocks false positives gets uninstalled, so every deny needs an escape
 * hatch that is explicit, reviewable and narrow:
 *
 * 1. Inline:  `// safepush-ignore KNOWN_SECRET -- synthetic fixture` on the same or previous
 *    line. A rule id AND a reason are required; a bare `safepush-ignore` does nothing.
 * 2. File:    `.safepush.json` at the repository root, committed and code-reviewed.
 *
 * Suppressions never apply to secret-file reads or `--no-verify`, and are ignored entirely
 * when the policy file itself is being written by the agent (see isPolicyFile).
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
export const DEFAULT_POLICY = {
    mode: 'balanced',
    ignorePaths: [],
    disabledRules: [],
    guards: { prompt: true, output: true, sinks: true, agentConfig: true },
};
const POLICY_FILE = '.safepush.json';
const MAX_POLICY_BYTES = 64 * 1024;
export function isPolicyFile(path) {
    return path.replaceAll('\\', '/').split('/').pop() === POLICY_FILE;
}
/** Loads .safepush.json. Invalid policy falls back to defaults rather than to "allow all". */
export function loadPolicy(repoRoot) {
    let raw;
    try {
        raw = readFileSync(join(repoRoot, POLICY_FILE), 'utf8');
    }
    catch {
        return DEFAULT_POLICY;
    }
    if (raw.length > MAX_POLICY_BYTES)
        return DEFAULT_POLICY;
    try {
        const p = JSON.parse(raw);
        return {
            mode: p.mode === 'strict' || p.mode === 'audit' ? p.mode : 'balanced',
            ignorePaths: Array.isArray(p.ignorePaths) ? p.ignorePaths.filter(x => typeof x === 'string').slice(0, 200) : [],
            disabledRules: Array.isArray(p.disabledRules) ? p.disabledRules.filter((x) => typeof x === 'string') : [],
            guards: { ...DEFAULT_POLICY.guards, ...(typeof p.guards === 'object' && p.guards ? p.guards : {}) },
        };
    }
    catch {
        return DEFAULT_POLICY;
    }
}
/** Minimal glob: `**` any path, `*` any segment chars, `?` one char. No dependencies. */
export function globToRegExp(glob) {
    let re = '';
    for (let i = 0; i < glob.length; i++) {
        const c = glob[i];
        if (c === '*' && glob[i + 1] === '*') {
            re += '.*';
            i++;
            if (glob[i + 1] === '/')
                i++;
        }
        else if (c === '*')
            re += '[^/]*';
        else if (c === '?')
            re += '[^/]';
        else
            re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
    return new RegExp('^' + re + '$');
}
const inlineIgnore = /safepush-ignore\s+([A-Z_]+(?:\s*,\s*[A-Z_]+)*)\s+--\s+\S.{2,}/;
function inlineSuppressed(f, lines) {
    if (!lines || !f.line)
        return false;
    for (const candidate of [lines[f.line - 1], lines[f.line - 2]]) {
        const m = candidate ? inlineIgnore.exec(candidate) : null;
        if (m && m[1].split(/\s*,\s*/).includes(f.rule))
            return true;
    }
    return false;
}
export function applyPolicy(findings, policy, sources) {
    const ignored = policy.ignorePaths.map(globToRegExp);
    return findings.filter(f => !policy.disabledRules.includes(f.rule) &&
        !ignored.some(re => re.test(f.file)) &&
        !inlineSuppressed(f, sources?.get(f.file)));
}
/** Maps a finding severity to a hook decision under the policy. */
export function decisionFor(severity, policy) {
    if (policy.mode === 'audit')
        return null;
    if (severity === 'high' || policy.mode === 'strict')
        return 'deny';
    return 'ask';
}
