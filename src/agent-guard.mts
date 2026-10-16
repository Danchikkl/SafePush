#!/usr/bin/env node
/**
 * Experimental Claude Code PreToolUse gate.
 *
 * Fail-closed allowlist for built-in file tools only. This is NOT an OS sandbox:
 * users/agents with other channels or permission to alter hook settings can bypass it.
 * Never echo input, paths, credentials, or error details.
 */
import { readFileSync, realpathSync, lstatSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { scanContent } from './rules.mjs';

const MAX_BYTES = 64 * 1024;
type Obj = Record<string, unknown>;
function object(x: unknown): x is Obj {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}
function blocked(path: string): boolean {
  const chunks = path.replaceAll('\\', '/').split('/').filter(Boolean);
  return chunks.some((part) =>
    part === '.git' || part === '.ssh' || part === '.aws' ||
    part === '.config' || part === '.claude' ||
    /^(?:\.env(?:\..*)?|\.npmrc|\.pypirc|\.netrc|id_(?:rsa|ed25519|ecdsa).*|credentials(?:\..*)?|secrets?(?:\..*)?|.*\.(?:pem|p12|pfx|key|kdbx))$/i.test(part)
  );
}
function deny(): void {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: 'SafePush Agent Guard: tool or path is outside the strict allowlist. Request an authorized workflow; do not expose credentials to the agent.',
    },
  }) + '\n');
}
function allowedPath(root: string, provided: unknown, exists: boolean): boolean {
  if (typeof provided !== 'string' || !provided || provided.includes('\0')) return false;
  if (blocked(provided)) return false;
  const absolute = resolve(root, provided);
  const rel = relative(root, absolute);
  if (!rel || rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel)) return false;
  if (blocked(rel)) return false;
  try {
    if (exists) {
      const physical = realpathSync(absolute);
      const actual = relative(root, physical);
      return Boolean(actual) && actual !== '..' && !actual.startsWith('..' + sep) &&
        !isAbsolute(actual) && !blocked(actual) && lstatSync(absolute).isFile();
    }
    // Avoid writing through symlinked parents or symlinked leaf paths.
    let current = root;
    const parts = rel.split(sep);
    for (const part of parts) {
      current = resolve(current, part);
      try {
        const st = lstatSync(current);
        if (st.isSymbolicLink()) return false;
      } catch (err) {
        if (!object(err) || err.code !== 'ENOENT') return false;
      }
    }
    return true;
  } catch { return false; }
}
function decision(root: string, data: unknown): boolean {
  if (!object(data) || typeof data.tool_name !== 'string' || !object(data.tool_input)) return false;
  const name = data.tool_name;
  const input = data.tool_input;
  // No terminal, search, notebooks, subagents or MCP tools: they can read or disclose secrets.
  if (!['Read', 'Write', 'Edit', 'MultiEdit'].includes(name)) return false;
  const path = input.file_path;
  if (name === 'Read') {
    if (!allowedPath(root, path, true)) return false;
    try {
      const file = resolve(root, path as string);
      const contents = readFileSync(file);
      if (contents.length > 1_000_000 || contents.includes(0)) return false;
      const findings = scanContent(file, contents.toString('utf8'));
      return !findings.some(f => f.rule === 'KNOWN_SECRET' || f.rule === 'GENERIC_SECRET_ASSIGNMENT');
    } catch { return false; }
  }
  if (name === 'Edit' || name === 'MultiEdit') return allowedPath(root, path, true);
  return allowedPath(root, path, false);
}
function main(): void {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== '--root') { deny(); return; }
  let root: string;
  try { root = realpathSync(resolve(args[1])); if (!lstatSync(root).isDirectory()) throw Error(); }
  catch { deny(); return; }
  let raw = '';
  try {
    raw = readFileSync(0, { encoding: 'utf8' });
    if (Buffer.byteLength(raw, 'utf8') > MAX_BYTES) { deny(); return; }
    if (!decision(root, JSON.parse(raw) as unknown)) deny();
  } catch { deny(); }
}
main();
