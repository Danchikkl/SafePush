/**
 * One entry point for every Claude Code hook event: `safepush hook claude`.
 * The plugin's hooks.json registers it for UserPromptSubmit, PreToolUse and PostToolUse.
 *
 *            stdin event JSON
 *                   |
 *        +----------+-----------+------------------+
 *        |                      |                  |
 * UserPromptSubmit         PreToolUse         PostToolUse
 *   promptGuard     sinkGuard -> evaluateClaudeHook   outputGuard
 *        |           (exfil)     (write/read/commit)    (redact)
 *        +----------+-----------+------------------+
 *                   |
 *            policy (mode, guards) -> audit log -> stdout JSON
 */
import { isAbsolute } from 'node:path';
import { audit } from './audit.mjs';
import { evaluateClaudeHook, hookOutput } from './claude-hook.mjs';
import { gitRoot } from './git.mjs';
import { outputGuard, promptGuard, sinkGuard } from './guards.mjs';
import { isPolicyFile, loadPolicy } from './policy.mjs';
const isRecord = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);
/** An agent edit that writes the policy file or adds an inline suppression. */
function policyTamper(tool, input) {
    const file = typeof input.file_path === 'string' ? input.file_path : typeof input.notebook_path === 'string' ? input.notebook_path : '';
    if (WRITE_TOOLS.has(tool) && file && isPolicyFile(file)) {
        return { decision: 'ask', reason: 'SafePush: the agent wants to change .safepush.json, which controls what SafePush blocks. Approve only if you asked for this change.' };
    }
    const text = [input.content, input.new_string, input.new_source,
        ...(Array.isArray(input.edits) ? input.edits.map(e => isRecord(e) ? e.new_string : '') : [])]
        .filter((v) => typeof v === 'string').join('\n');
    const command = tool === 'Bash' && typeof input.command === 'string' ? input.command : '';
    if ((WRITE_TOOLS.has(tool) && /safepush-ignore/.test(text)) || /safepush-ignore|\.safepush\.json/.test(command)) {
        return { decision: 'ask', reason: 'SafePush: the agent wants to add a safepush-ignore suppression or edit SafePush policy. Approve only if you asked to silence this finding.' };
    }
    return null;
}
export function routeClaudeHook(event, fallbackCwd = process.cwd()) {
    if (!isRecord(event))
        return '';
    const cwd = typeof event.cwd === 'string' && isAbsolute(event.cwd) ? event.cwd : fallbackCwd;
    const repo = gitRoot(cwd);
    const policy = loadPolicy(repo ?? cwd);
    const tool = typeof event.tool_name === 'string' ? event.tool_name : '';
    const input = isRecord(event.tool_input) ? event.tool_input : {};
    const log = (decision, guard) => audit(repo, { event: String(event.hook_event_name), tool, decision, guard });
    switch (event.hook_event_name) {
        case 'UserPromptSubmit': {
            if (!policy.guards.prompt || typeof event.prompt !== 'string')
                return '';
            const blocked = promptGuard(event.prompt);
            if (!blocked)
                return '';
            log(policy.mode === 'audit' ? 'audit' : 'block', 'prompt');
            return policy.mode === 'audit' ? '' : JSON.stringify(blocked);
        }
        case 'PreToolUse': {
            // The policy can switch guards off, so the agent must not change it on its own.
            // Checked before policy.mode: even audit mode asks.
            const tamper = policyTamper(tool, input);
            if (tamper) {
                log('ask', 'policy');
                return hookOutput(tamper);
            }
            const decision = (policy.guards.sinks ? sinkGuard(tool, input) : null) ?? evaluateClaudeHook(event, cwd);
            if (!decision)
                return '';
            log(policy.mode === 'audit' ? 'audit' : decision.decision, 'pre-tool');
            if (policy.mode === 'audit')
                return '';
            // strict mode escalates "ask" to "deny"
            return hookOutput(policy.mode === 'strict' ? { ...decision, decision: 'deny' } : decision);
        }
        case 'PostToolUse': {
            if (!policy.guards.output)
                return '';
            const replaced = outputGuard(tool, event.tool_response);
            if (!replaced)
                return '';
            log('redact', 'output');
            return JSON.stringify(replaced); // redaction is not a block, so audit mode still redacts
        }
        default:
            return '';
    }
}
