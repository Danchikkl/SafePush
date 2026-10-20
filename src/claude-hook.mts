/**
 * Opt-in adapter for Claude Code PreToolUse hooks.
 *
 * Nothing in SafePush registers this hook automatically. A user must add it to their own
 * Claude Code settings (see docs/claude-code-hooks.md). It reads one hook event as JSON and
 * returns a permission decision. It never edits files, never prints matched values and makes
 * no network requests.
 *
 * Decisions:
 * - deny: a high-severity credential would be written to a non-env file, a commit would
 *   include high-severity findings, or the agent tries to skip Git hooks.
 * - ask:  a medium/heuristic finding, a credential-looking value in a shell command, an env
 *   file that Git would not ignore, or a scan that could not complete.
 * - null: no opinion; Claude Code continues with its normal permission flow.
 */
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { gitExec, gitRoot } from './git.mjs';
import { isEnvFile, isEnvTemplate, redactKnownSecrets, scanContent } from './rules.mjs';
import { scan } from './scanner.mjs';
import type { Finding } from './types.mjs';

export type HookDecision = { decision: 'deny' | 'ask'; reason: string } | null;
type Json = Record<string, unknown>;

const MAX_LISTED = 5;
const NO_VALUES = 'SafePush never shows matched values; do not repeat them in chat either.';

function isRecord(v: unknown): v is Json {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function str(v: unknown): string | null {
  return typeof v === 'string' ? v : null;
}
function clean(text: string): string {
  return redactKnownSecrets(text).replace(/[\x00-\x1f\x7f-\x9f]/g, '?');
}
function displayPath(cwd: string, file: string): string {
  const abs = resolve(cwd, file);
  const rel = relative(cwd, abs);
  const inside = rel && rel !== '..' && !rel.startsWith('..' + sep) && !isAbsolute(rel);
  return clean((inside ? rel : abs).replaceAll('\\', '/'));
}
function list(findings: Finding[], withLines: boolean): string {
  const lines = findings.slice(0, MAX_LISTED).map(f =>
    '- ' + f.title + (withLines && f.line ? ' (line ' + f.line + ')' : '') + ' [' + f.rule + ']');
  if (findings.length > MAX_LISTED) lines.push('- …and ' + (findings.length - MAX_LISTED) + ' more');
  return lines.join('\n');
}

/** Text the tool is about to write, or null for tools SafePush does not inspect. */
function proposedText(tool: string, input: Json): { file: string; text: string; partial: boolean } | null {
  const file = str(input.file_path) ?? str(input.notebook_path);
  if (!file) return null;
  if (tool === 'Write') {
    const text = str(input.content);
    return text === null ? null : { file, text, partial: false };
  }
  if (tool === 'Edit') {
    const text = str(input.new_string);
    return text === null ? null : { file, text, partial: true };
  }
  if (tool === 'MultiEdit' && Array.isArray(input.edits)) {
    const parts = input.edits.map(e => isRecord(e) ? str(e.new_string) : null);
    if (parts.some(p => p === null)) return null;
    return { file, text: parts.join('\n'), partial: true };
  }
  if (tool === 'NotebookEdit') {
    const text = str(input.new_source);
    return text === null ? null : { file, text, partial: true };
  }
  return null;
}

/** true = ignored, false = would be committable, null = not a Git repository. */
function gitIgnores(cwd: string, absFile: string): boolean | null {
  const root = gitRoot(cwd);
  if (!root) return null;
  try {
    gitExec(root, ['check-ignore', '-q', '--', absFile]);
    return true;
  } catch (error) {
    // Exit status 1 means "not ignored"; anything else is an unexpected Git failure.
    if (isRecord(error) && error.status === 1) return false;
    throw error;
  }
}

function checkWrite(cwd: string, file: string, text: string, partial: boolean): HookDecision {
  const abs = resolve(cwd, file);
  const shown = displayPath(cwd, file);
  const findings = scanContent(shown, text);

  if (isEnvFile(abs) && !isEnvTemplate(abs)) {
    // A real .env file is the right home for secrets, provided Git will ignore it.
    const ignored = gitIgnores(cwd, abs);
    if (ignored === false) {
      return { decision: 'ask', reason:
        'SafePush: ' + shown + ' is an environment file that Git would NOT ignore, so its values could be committed. ' +
        'Add .env and .env.* to .gitignore first (`safepush init`), or confirm this file is meant to be tracked.' };
    }
    const exposed = findings.filter(f => f.rule === 'CLIENT_EXPOSED_SECRET_NAME');
    if (exposed.length) {
      return { decision: 'ask', reason:
        'SafePush: ' + shown + ' defines a browser-public variable (NEXT_PUBLIC_/VITE_/REACT_APP_) with a sensitive-looking name. ' +
        'Such values are bundled into client code. If it is a server secret, drop the public prefix and use it only in server code.\n' +
        list(exposed, !partial) };
    }
    return null;
  }

  if (!findings.length) return null;
  const high = findings.filter(f => f.severity === 'high');
  const where = partial ? 'in the proposed edit to ' + shown : 'in ' + shown;
  const advice =
    'Do not hardcode credentials. Read the value from a server-side environment variable (for example process.env.NAME), ' +
    'put a placeholder in .env.example, and ask the user to place the real value in their ignored .env file. ' + NO_VALUES;
  if (high.length) {
    return { decision: 'deny', reason: 'SafePush blocked this write: likely credential ' + where + '.\n' + list(high, !partial) + '\n' + advice };
  }
  return { decision: 'ask', reason: 'SafePush: possible credential or risky public variable ' + where + ' (heuristic, may be a false positive).\n' +
    list(findings, !partial) + '\n' + advice };
}

const commitPattern = /\bgit\b((?:\s+-(?:C|c)\s+\S+)*)\s+commit\b([^\n]*)/;

function checkBash(cwd: string, command: string): HookDecision {
  for (const segment of command.split(/&&|\|\||[;|\n]/)) {
    const match = commitPattern.exec(segment);
    if (!match) continue;
    const args = ' ' + match[2] + ' ';
    if (/\s--no-verify\s|\s-n\s/.test(args)) {
      return { decision: 'deny', reason:
        'SafePush: committing with --no-verify skips the project\'s Git hooks, including secret checks. ' +
        'Commit without it. If a hook is failing, show the user the hook output and let them decide.' };
    }
    const dirFlag = /-C\s+(\S+)/.exec(match[1]);
    const dir = resolve(cwd, dirFlag ? dirFlag[1].replace(/^['"]|['"]$/g, '') : '.');
    // `git commit -a` also commits modified tracked files that are not staged yet.
    const includesWorktree = /\s(?:--all|-[A-Za-z]*a[A-Za-z]*)\s/.test(args);
    let findings: Finding[];
    try {
      if (!gitRoot(dir)) continue;
      findings = scan({ root: dir, staged: !includesWorktree }).findings;
    } catch {
      return { decision: 'ask', reason:
        'SafePush could not complete its pre-commit scan (for example, an oversized or binary staged file). ' +
        'Treat this as unchecked, not clean. Run `safepush scan --staged` locally before committing.' };
    }
    const high = findings.filter(f => f.severity === 'high');
    if (high.length) {
      const files = high.map(f => ({ ...f, title: f.title + ' — ' + clean(f.file) + (f.line ? ':' + f.line : '') }));
      return { decision: 'deny', reason:
        'SafePush blocked this commit: ' + high.length + ' high-severity finding(s) in ' + (includesWorktree ? 'files that `-a` would commit' : 'the staged changes') + '.\n' +
        list(files, false) + '\n' +
        'Remove the credential from code (use environment variables), unstage tracked .env files with `git rm --cached -- <file>`, then retry. ' +
        'If a real credential was already committed or pushed earlier, tell the user it must be rotated. ' + NO_VALUES };
    }
  }

  const inCommand = scanContent('command', command).filter(f => f.rule === 'KNOWN_SECRET');
  if (inCommand.length) {
    return { decision: 'ask', reason:
      'SafePush: this shell command contains a value that looks like a credential (' + inCommand[0].title.replace(/^Possible /, '') + '). ' +
      'Commands end up in shell history, logs and transcripts. Prefer reading the value from an environment variable. ' + NO_VALUES };
  }
  return null;
}

export function evaluateClaudeHook(event: unknown, fallbackCwd = process.cwd()): HookDecision {
  if (!isRecord(event) || event.hook_event_name !== 'PreToolUse') return null;
  const tool = str(event.tool_name);
  const input = event.tool_input;
  if (!tool || !isRecord(input)) return null;
  const cwdValue = str(event.cwd);
  const cwd = cwdValue && isAbsolute(cwdValue) ? cwdValue : fallbackCwd;

  if (tool === 'Bash') {
    const command = str(input.command);
    return command ? checkBash(cwd, command) : null;
  }
  const proposed = proposedText(tool, input);
  return proposed ? checkWrite(cwd, proposed.file, proposed.text, proposed.partial) : null;
}

export function hookOutput(decision: HookDecision): string {
  if (!decision) return '';
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: decision.decision,
      permissionDecisionReason: decision.reason,
    },
  });
}
