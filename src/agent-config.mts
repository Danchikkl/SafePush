/**
 * Agent configuration and instruction-file checks.
 *
 * AI tooling added a new class of files that hold secrets or steer the agent:
 *   - MCP / agent configs:   .mcp.json, .cursor/mcp.json, .vscode/mcp.json,
 *                            claude_desktop_config.json, .claude/settings*.json, .gemini/settings.json
 *   - Instruction files:     CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, .cursor/rules/*,
 *                            .github/copilot-instructions.md, SKILL.md
 * Configs leak literal tokens in `env`/`headers`; project-level settings can redirect API
 * traffic (e.g. ANTHROPIC_BASE_URL) or register hooks; instruction files can hide prompts in
 * invisible Unicode. Called from scanner.mts for every scanned file.
 */
import { finding, knownSecretProviders } from './rules.mjs';
import type { Finding } from './types.mjs';

const agentConfig = /(?:^|\/)(?:\.mcp\.json|mcp\.json|claude_desktop_config\.json|\.claude\/settings(?:\.local)?\.json|\.gemini\/settings\.json)$/i;
const instructionFile = /(?:^|\/)(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|copilot-instructions\.md|SKILL\.md|\.cursor\/rules\/[^/]+)$/i;

const secretKey = /(?:token|secret|password|passwd|api[_-]?key|authorization|auth|cookie|private[_-]?key|credential)/i;
const reference = /^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\{\{.*\}\}|<.*>|op:\/\/|env:|keychain:|\$\(.*\))$|^(?:Bearer\s+)?\$\{?[A-Za-z_]/;
const redirectVar = /^(?:ANTHROPIC_BASE_URL|ANTHROPIC_BEDROCK_BASE_URL|ANTHROPIC_VERTEX_BASE_URL|OPENAI_BASE_URL|OPENAI_API_BASE|HTTPS?_PROXY|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED)$/i;
// Invisible or direction-changing characters: Unicode tags (used to smuggle ASCII), bidi
// overrides/isolates, zero-width characters and a BOM that is not at the start of the file.
const hiddenUnicode = /[\u{E0000}-\u{E007F}‪-‮⁦-⁩​-‏⁠-⁤﻿]/u;

export function isAgentConfig(path: string): boolean { return agentConfig.test(path); }
export function isInstructionFile(path: string): boolean { return instructionFile.test(path); }

/** Walks parsed JSON, calling visit(keyPath, value) for every string leaf. */
function walk(node: unknown, path: string[], visit: (path: string[], value: string) => void, depth = 0): void {
  if (depth > 30) return;
  if (typeof node === 'string') visit(path, node);
  else if (Array.isArray(node)) node.forEach((v, i) => walk(v, [...path, String(i)], visit, depth + 1));
  else if (node && typeof node === 'object') for (const [k, v] of Object.entries(node)) walk(v, [...path, k], visit, depth + 1);
}

function lineOf(text: string, needle: string): number | undefined {
  const i = text.indexOf(needle);
  return i < 0 ? undefined : text.slice(0, i).split('\n').length;
}

export function scanAgentConfig(path: string, text: string): Finding[] {
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { return []; } // JSONC/TOML: plain rules still apply
  const findings: Finding[] = [];
  const projectLevel = !/claude_desktop_config\.json$|\.local\.json$/i.test(path);
  walk(parsed, [], (keys, value) => {
    const key = keys[keys.length - 1] ?? '';
    const inEnvOrHeaders = keys.some(k => k === 'env' || k === 'headers');
    const literal = value.trim();
    const known = knownSecretProviders(literal);
    const looksSecret = known.length > 0 ||
      (inEnvOrHeaders && secretKey.test(key) && literal.length >= 16 && !reference.test(literal));
    if (looksSecret) {
      findings.push(finding('AGENT_CONFIG_SECRET', 'high', path, lineOf(text, JSON.stringify(key)),
        'Literal credential in agent/MCP configuration (' + keys.slice(-3).join('.') + ')',
        'Agent configs are often committed, synced or shared with teammates and plugins. Thousands of live keys have been found in public MCP configs.',
        'Reference an environment variable instead, e.g. "${GITHUB_TOKEN}", and set it outside the repository.'));
    }
    if (projectLevel && keys.includes('env') && redirectVar.test(key)) {
      findings.push(finding('AGENT_CONFIG_RISK', 'high', path, lineOf(text, JSON.stringify(key)),
        'Project config overrides ' + key,
        'A repository-level setting can send your API key or traffic to another server as soon as the project is opened.',
        'Remove it from shared config. Set endpoints in your user-level settings only, and only for servers you control.'));
    }
  });
  if (projectLevel && /\.claude\/settings\.json$/i.test(path) && /"hooks"\s*:/.test(text) && /\b(?:curl|wget|nc|bash\s+-c|sh\s+-c|base64)\b/.test(text)) {
    findings.push(finding('AGENT_CONFIG_RISK', 'medium', path, lineOf(text, '"hooks"'),
      'Shared Claude Code settings register hooks that run network or shell commands',
      'Hooks in a committed settings file run on every teammate\'s machine. Review them like CI scripts.',
      'Keep personal hooks in .claude/settings.local.json; review shared hooks in code review.'));
  }
  if (projectLevel && /"enableAllProjectMcpServers"\s*:\s*true/.test(text)) {
    findings.push(finding('AGENT_CONFIG_RISK', 'medium', path, lineOf(text, 'enableAllProjectMcpServers'),
      'All project MCP servers are auto-approved',
      'Any MCP server added to the repository later starts without an approval prompt.',
      'Approve servers individually instead.'));
  }
  return findings;
}

export function scanInstructionFile(path: string, text: string): Finding[] {
  const findings: Finding[] = [];
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    const body = index === 0 ? line.replace(/^﻿/, '') : line;
    if (hiddenUnicode.test(body)) {
      findings.push(finding('HIDDEN_UNICODE', 'medium', path, index + 1,
        'Invisible or bidirectional Unicode in an agent instruction file',
        'Agents read characters that reviewers cannot see. Hidden text in instruction files is a known prompt-injection technique.',
        'Remove the characters or replace the line with plain text, then review what it said.'));
    }
  }
  return findings;
}
