#!/usr/bin/env node
/**
 * Small, dependency-free MCP stdio adapter for SafePush.
 *
 * Implements the read-only tools subset for the 2025-06-18/2025-11-25
 * initialization-based protocol and the 2026-07-28 stateless protocol.
 * It is not a general-purpose MCP SDK.
 *
 * stdout is reserved exclusively for newline-delimited JSON-RPC.
 */
import { lstatSync, realpathSync } from 'node:fs';
import { relative, resolve } from 'node:path';
import { gitRoot } from './git.mjs';
import { redactKnownSecrets } from './rules.mjs';
import { scan } from './scanner.mjs';

const SERVER = { name: 'safepush', version: '0.1.0' };
const MODERN = '2026-07-28';
const LEGACY = ['2025-11-25', '2025-06-18'];
const SUPPORTED = [MODERN, ...LEGACY];
const MAX_INPUT_CHARS = 262_144;
const MAX_FINDINGS = 100;
const TOOL = {
  name: 'safepush_scan',
  title: 'SafePush local secret scan',
  description: 'Read-only scan of the project fixed when the server starts. Checks common secret patterns, tracked .env files, and browser-public env names. Never validates credentials. A clean result is not a security audit. Use staged=true before committing.',
  inputSchema: {
    type: 'object',
    properties: { staged: { type: 'boolean', description: 'Check staged Git index content instead of workspace files.' } },
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
};

type JsonObject = Record<string, unknown>;
type RequestId = string | number | null;
function record(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function safeText(value: string): string {
  return redactKnownSecrets(value).replace(/[\x00-\x1f\x7f-\x9f]/g, '?');
}
function send(value: JsonObject): void {
  process.stdout.write(JSON.stringify(value) + '\n');
}
function success(id: RequestId, result: JsonObject, modern = false): void {
  send({ jsonrpc: '2.0', id, result: modern ? {
    resultType: 'complete',
    ...result,
    _meta: { 'io.modelcontextprotocol/serverInfo': SERVER },
  } : result });
}
function failure(id: RequestId, code: number, message: string, data?: JsonObject): void {
  send({ jsonrpc: '2.0', id, error: { code, message, ...(data ? { data } : {}) } });
}
function projectRoot(args: string[]): string {
  if (args.length !== 0 && (args.length !== 2 || args[0] !== '--root' || !args[1])) {
    throw new Error('Usage: node dist/mcp.mjs [--root /absolute/project/path]');
  }
  const root = realpathSync(resolve(args[1] ?? process.cwd()));
  if (!lstatSync(root).isDirectory()) throw new Error('Project root must be a directory.');
  const repository = gitRoot(root);
  if (repository && relative(root, realpathSync(repository)) !== '') {
    throw new Error('Use the Git repository root, not a subdirectory, to avoid scanning outside the selected path.');
  }
  return root;
}
function toolResult(root: string, args: unknown): JsonObject {
  if (args === undefined) args = {};
  if (!record(args) || Object.keys(args).some(key => key !== 'staged') ||
      (args.staged !== undefined && typeof args.staged !== 'boolean')) {
    throw new TypeError('Invalid tool arguments: only optional boolean "staged" is allowed.');
  }
  const result = scan({ root, staged: args.staged === true });
  const findings = result.findings.slice(0, MAX_FINDINGS).map(f => ({
    ...f,
    file: safeText(f.file),
  }));
  const report = {
    mode: result.mode,
    filesScanned: result.filesScanned,
    skippedLargeOrBinary: result.skippedLargeOrBinary,
    frameworks: result.frameworks,
    findings,
    totalFindings: result.findings.length,
    truncated: result.findings.length > MAX_FINDINGS,
    disclaimer: 'Pattern/heuristic scan only; no credentials validated. No findings does not mean secure. Paths and line numbers may be sensitive.',
  };
  return {
    content: [{ type: 'text', text: JSON.stringify(report) }],
    // Structured results are optional for legacy clients, and supported by newer clients.
    structuredContent: report,
    isError: false,
  };
}
function toolError(message: string): JsonObject {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function runServer(root: string): void {
  let legacyInitialized = false;
  let pending = '';

  function handle(message: unknown): void {
    if (!record(message) || message.jsonrpc !== '2.0' || typeof message.method !== 'string') {
      failure(null, -32600, 'Invalid JSON-RPC request');
      return;
    }
    const hasId = Object.hasOwn(message, 'id');
    if (!hasId) return; // Notifications never receive a response.
    const id = message.id;
    if (!(typeof id === 'string' || (typeof id === 'number' && Number.isSafeInteger(id)))) {
      failure(null, -32600, 'Invalid JSON-RPC id');
      return;
    }
    const params = message.params;
    if (params !== undefined && !record(params)) {
      failure(id, -32602, 'Invalid params');
      return;
    }
    const meta = record(params) && record(params._meta) ? params._meta : null;
    const requestedVersion = meta?.['io.modelcontextprotocol/protocolVersion'];
    const modern = requestedVersion !== undefined;

    if (modern) {
      if (typeof requestedVersion !== 'string') {
        failure(id, -32602, 'Invalid protocol version metadata');
        return;
      }
      if (!SUPPORTED.includes(requestedVersion) || requestedVersion !== MODERN) {
        failure(id, -32022, 'Unsupported protocol version', {
          requested: requestedVersion, supported: SUPPORTED,
        });
        return;
      }
      if (!record(meta?.['io.modelcontextprotocol/clientCapabilities'])) {
        failure(id, -32602, 'Missing client capabilities metadata');
        return;
      }
    }

    if (message.method === 'server/discover') {
      if (!modern) { failure(id, -32601, 'Method not found'); return; }
      success(id, {
        supportedVersions: SUPPORTED,
        capabilities: { tools: { listChanged: false } },
        instructions: 'Only safepush_scan is exposed. The server scans the project pinned at startup, never edits files or validates tokens.',
      }, true);
      return;
    }
    if (message.method === 'initialize') {
      if (modern) { failure(id, -32602, 'Legacy initialization is not used with modern metadata'); return; }
      const requested = record(params) && typeof params.protocolVersion === 'string' ? params.protocolVersion : null;
      if (!requested || !record(params) || !record(params.capabilities) || !record(params.clientInfo)) {
        failure(id, -32602, 'Invalid initialize params');
        return;
      }
      legacyInitialized = true;
      success(id, {
        protocolVersion: LEGACY.includes(requested) ? requested : LEGACY[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER,
        instructions: 'Read-only local project scanner. No matched credential values are returned.',
      });
      return;
    }
    if (!modern && !legacyInitialized) {
      failure(id, -32600, 'Initialize MCP before requesting tools');
      return;
    }
    if (message.method === 'ping') { success(id, {}, modern); return; }
    if (message.method === 'tools/list') {
      success(id, { tools: [TOOL] }, modern);
      return;
    }
    if (message.method === 'tools/call') {
      if (!record(params) || params.name !== TOOL.name) {
        failure(id, -32602, 'Unknown tool name');
        return;
      }
      try {
        success(id, toolResult(root, params.arguments), modern);
      } catch (error) {
        // Never include raw exception text: Git errors may contain secret-shaped paths.
        const message = error instanceof TypeError
          ? 'Invalid arguments: only optional boolean "staged" is allowed.'
          : 'Scan failed or was incomplete. Run SafePush CLI locally for details; do not treat this as a clean scan.';
        success(id, toolError(message), modern);
      }
      return;
    }
    failure(id, -32601, 'Method not found');
  }

  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk: string) => {
    pending += chunk;
    if (pending.length > MAX_INPUT_CHARS) {
      failure(null, -32700, 'Input message too large');
      process.stdin.destroy();
      process.exitCode = 2;
      return;
    }
    let newline = pending.indexOf('\n');
    while (newline !== -1) {
      const line = pending.slice(0, newline).trim();
      pending = pending.slice(newline + 1);
      if (line) {
        try { handle(JSON.parse(line) as unknown); }
        catch { failure(null, -32700, 'Parse error'); }
      }
      newline = pending.indexOf('\n');
    }
  });
  process.stdin.on('end', () => { pending = ''; });
}

try {
  runServer(projectRoot(process.argv.slice(2)));
} catch {
  // The MCP wire protocol must never be contaminated with startup diagnostics.
  process.stderr.write('SafePush MCP: invalid project root or startup arguments.\n');
  process.exitCode = 2;
}
