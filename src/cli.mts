#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync, openSync, closeSync, appendFileSync, fstatSync, lstatSync, realpathSync, constants } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { gitExec, gitRoot } from './git.mjs';
import { envIgnoreMissing, redactKnownSecrets } from './rules.mjs';
import { scan } from './scanner.mjs';
import { routeClaudeHook } from './hook-router.mjs';
import { toSarif } from './sarif.mjs';
import type { Finding, ScanResult } from './types.mjs';

const VERSION = '0.1.0';
const USAGE = [
  'SafePush v' + VERSION + ' — security guardrails for AI-built apps',
  '',
  'Usage:',
  '  safepush scan [path] [--staged] [--strict] [--json]',
  '  safepush init [path] [--hook]',
  '  safepush explain <rule-id>',
  '  safepush hook claude        (reads a Claude Code PreToolUse event on stdin)',
  '  safepush --help',
  '',
  'Commands:',
  '  scan       Scan local files without uploading contents',
  '  init       Add .env ignore rules; optionally install a pre-commit hook',
  '  explain    Show recovery guidance',
  '  hook       Opt-in Claude Code hook adapter; see docs/claude-code-hooks.md',
  '',
  'Options:',
  '  --staged   Scan exact file contents in the Git index',
  '  --strict   Exit 1 for medium findings too',
  '  --json     Structured report without secret values',
  '  --hook     With init: install a hook without replacing one',
].join('\n');

const explain: Record<string,string> = {
  KNOWN_SECRET: 'Possible exposed token. Never test someone else\'s credentials. If yours: revoke/rotate it, replace usages, and inspect Git history. Deleting one line is not enough.',
  GENERIC_SECRET_ASSIGNMENT: 'A sensitive variable appears to contain a long literal. Verify locally and, if real, revoke and move it to server-side configuration. Heuristics can be wrong.',
  TRACKED_ENV_FILE: 'A .env file is in the Git index. First, if its credentials were pushed or otherwise exposed, revoke/rotate them at the provider and update dependent services. Then add appropriate .gitignore rules and run git rm --cached -- path/to/.env to stop tracking without deleting your local file. Commit that removal. Ignoring a file never untracks it, and deleting it now does not erase old Git commits. Review history separately and seek help before rewriting shared history.',
  CLIENT_EXPOSED_SECRET_NAME: 'NEXT_PUBLIC_, VITE_, and REACT_APP_ can expose values in browser builds. Public identifiers may be fine, but server secrets must stay server-side.',
  ENV_GITIGNORE_MISSING: 'Ignore .env and .env.* except intentional templates. Run safepush init. This will not untrack files already committed.',
};
function sanitize(text: string): string {
  return redactKnownSecrets(text).replace(/[\x00-\x1f\x7f-\x9f]/g, '?');
}
function summarize(result: ScanResult): void {
  console.log('SafePush v' + VERSION + '  ·  ' + result.mode + '  ·  ' + result.filesScanned + ' file(s) scanned');
  if (result.frameworks.length) console.log('Framework: ' + result.frameworks.join(', '));
  if (result.skippedLargeOrBinary) console.log('Skipped ' + result.skippedLargeOrBinary + ' oversized/binary file(s) (not scanned).');
  if (!result.findings.length) {
    console.log('No issues found by current rules. This is NOT a full security audit.');
    return;
  }
  console.log(result.findings.length + ' finding(s):\n');
  for (const f of result.findings) {
    const where = sanitize(f.file + (f.line ? ':' + f.line : ''));
    console.log('[' + f.severity.toUpperCase() + '] ' + f.rule + ' — ' + where);
    console.log('  ' + f.title);
    console.log('  Priority: ' + (f.priority ?? 'review') + ' (triage hint, not an exploitability score)');
    if (f.evidence) console.log('  Evidence: ' + f.evidence.summary);
    if (f.verify) console.log('  Verify: ' + f.verify);
    console.log('  Why: ' + f.why);
    console.log('  Fix: ' + f.fix + '\n');
  }
  console.log('SafePush never prints matched credential values. Rotate any real leaked credentials.');
}
function addIgnoreRules(root: string): void {
  const path = join(root, '.gitignore');
  if (existsSync(path) && !lstatSync(path).isFile()) {
    throw new Error('Refusing to modify a non-regular or symlinked .gitignore file.');
  }
  const flags = constants.O_RDWR | constants.O_APPEND | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0);
  const fd = openSync(path, flags, 0o644);
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.size > 2_000_000) {
      throw new Error('Refusing to modify a non-regular or oversized .gitignore file.');
    }
    const old = readFileSync(fd, 'utf8');
    if (!envIgnoreMissing(old)) {
      console.log('.gitignore: existing env ignore patterns detected; unchanged.');
      return;
    }
    const lines = '\n# SafePush: keep real environment files out of Git\n.env\n.env.*\n!.env.example\n!.env.sample\n!.env.template\n!.env.*.example\n!.env.*.sample\n!.env.*.template\n';
    appendFileSync(fd, (old && !old.endsWith('\n') ? '\n' : '') + lines, 'utf8');
  } finally {
    closeSync(fd);
  }
  console.log('.gitignore: added common env ignore patterns (review before committing).');
}
function hookLocation(root: string): string {
  const repoRoot = gitRoot(root);
  if (!repoRoot) throw new Error('Cannot install Git hook outside a Git repository.');
  const configured = String(gitExec(repoRoot, ['config', '--get', '--default', '', 'core.hooksPath'], {encoding:'utf8'})).trim();
  if (configured) throw new Error('Custom core.hooksPath detected. Install the hook manually.');
  const gitDir = realpathSync(String(gitExec(repoRoot, ['rev-parse', '--absolute-git-dir'], {encoding:'utf8'})).trim());
  const hookDir = join(gitDir, 'hooks');
  if (existsSync(hookDir) && (lstatSync(hookDir).isSymbolicLink() || !lstatSync(hookDir).isDirectory())) {
    throw new Error('Refusing to write into a symlinked/non-directory Git hooks path.');
  }
  return join(hookDir, 'pre-commit');
}
function addHook(path: string): void {
  if (existsSync(path)) {
    console.log('Existing pre-commit hook found. Not modified. Add "./node_modules/.bin/safepush scan --staged" manually.');
    return;
  }
  mkdirSync(dirname(path), {recursive:true});
  const hook = [
    '#!/bin/sh',
    '# Installed by SafePush. Requires locally installed devDependency.',
    'if [ ! -x "./node_modules/.bin/safepush" ]; then',
    '  echo "SafePush: missing local CLI. Run npm install (or remove the hook)." >&2',
    '  exit 1',
    'fi',
    './node_modules/.bin/safepush scan --staged',
    ''
  ].join('\n');
  writeFileSync(path, hook, {mode:0o755, flag:'wx'});
  chmodSync(path, 0o755);
  console.log('Git pre-commit hook installed; did not replace an existing hook.');
}
const MAX_HOOK_INPUT = 16 * 1024 * 1024;
function runClaudeHook(): number {
  // This opt-in security hook blocks if its input cannot be checked.
  // Claude Code treats exit code 2 as a blocking hook error.
  const raw = readFileSync(0);
  if (raw.length > MAX_HOOK_INPUT) { console.error('SafePush hook blocked: input too large; not checked.'); return 2; }
  let event: unknown;
  try { event = JSON.parse(raw.toString('utf8')); }
  catch { console.error('SafePush hook blocked: invalid JSON input; not checked.'); return 2; }
  const out = routeClaudeHook(event);
  if (out) process.stdout.write(out + '\n');
  return 0;
}
function main(args: string[]): number {
  const [command = '--help', ...rest] = args;
  if (command === '--help' || command === '-h' || command === 'help') { console.log(USAGE); return 0; }
  if (command === '--version' || command === '-v') { console.log(VERSION); return 0; }
  if (command === 'explain') {
    const rule = rest[0]?.toUpperCase();
    if (!rule || !explain[rule]) { console.error('Unknown rule. Choices: ' + Object.keys(explain).join(', ')); return 2; }
    console.log(rule + '\n\n' + explain[rule]);
    return 0;
  }
  if (command === 'hook') {
    if (rest.length !== 1 || rest[0] !== 'claude') { console.error('Usage: safepush hook claude'); return 2; }
    return runClaudeHook();
  }
  if (command !== 'scan' && command !== 'init') { console.error('Unknown command: ' + command + '\n\n' + USAGE); return 2; }
  const knownFlags = new Set(command === 'scan' ? ['--staged','--strict','--json','--sarif'] : ['--hook']);
  const unknown = rest.filter(x => x.startsWith('--') && !knownFlags.has(x));
  if (unknown.length) { console.error('Unknown option: ' + unknown.join(', ')); return 2; }
  const paths = rest.filter(x => !x.startsWith('--'));
  if (paths.length > 1) { console.error('Provide at most one path.'); return 2; }
  const root = resolve(paths[0] ?? process.cwd());
  if (!existsSync(root)) { console.error('Path not found: ' + sanitize(root)); return 2; }
  if (command === 'init') {
    const hookPath = rest.includes('--hook') ? hookLocation(root) : null;
    addIgnoreRules(root);
    if (hookPath) addHook(hookPath);
    console.log('Next: safepush scan .  (No credential data is transmitted.)');
    return 0;
  }
  const result = scan({root, staged:rest.includes('--staged')});
  if (rest.includes('--sarif')) {
    console.log(JSON.stringify(toSarif({...result, findings:result.findings.map(f => ({...f, file:sanitize(f.file)}))}, VERSION), null, 2));
  } else if (rest.includes('--json')) {
    const {root: _localRoot, ...publicResult} = result;
    console.log(JSON.stringify({...publicResult, findings:result.findings.map(f => ({...f, file:sanitize(f.file)}))}, null, 2));
  } else summarize(result);
  return result.findings.some((f: Finding) => f.severity === 'high' || rest.includes('--strict')) ? 1 : 0;
}
try { process.exitCode = main(process.argv.slice(2)); }
catch (error) {
  console.error('SafePush error: ' + sanitize(error instanceof Error ? error.message : String(error)));
  process.exitCode = 2;
}
