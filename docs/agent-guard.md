# Experimental SafePush Agent Guard for Claude Code

**Security status: research prototype. This hook is NOT a secrets vault, OS sandbox, or proven prevention of agent exfiltration.**

This opt-in Claude Code `PreToolUse` gate enforces a **strict allowlist** on tool calls that pass through the hook. It permits only built-in `Read`, `Write`, `Edit`, and `MultiEdit` for regular project files. It denies sensitive paths (`.env*`, `.ssh/`, `.aws/`, `.git/`, private-key formats, credential files), paths outside the selected project, symlink escapes, all terminal commands (`Bash`), search tools (`Grep` / `Glob`), delegation, and unknown/MCP tools. It fails closed on malformed input and emits only fixed denial messages.

The strong restrictions are intentional: arbitrary shell commands or an alternative tool would otherwise bypass file-read rules. The policy will seriously limit normal coding and testing tasks. Use it only to evaluate compatibility with **synthetic secrets**.

## Setup

Build from an inspected SafePush checkout:

```sh
npm ci --ignore-scripts
npm run build
```

Add this hook to your **local user settings** (`~/.claude/settings.json`), replacing both absolute paths with real paths. Review existing settings and merge rather than overwriting them:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "node /ABS/PATH/TO/SafePush/dist/agent-guard.mjs --root /ABS/PATH/TO/PROJECT"
          }
        ]
      }
    ]
  }
}
```

The hook prints nothing for allow; returns a structured `permissionDecision: deny` for blocked calls. **Do not** install this as an agent-editable project setting and call it an enforcement boundary. Review the behavior against the [current Claude Code hooks documentation](https://code.claude.com/docs/en/hooks) before use.

The process running the hook can read local paths to validate them but does not read secret **contents**. Reports do not include paths or supplied input.

## Boundaries and limitations

- This is **tool interception, not file isolation**. An agent with other execution channels, uncontrolled plugins, access to processes holding secrets, or control of the hook configuration can bypass it.
- Readable source files may themselves contain hardcoded credentials; this prototype does **not** inspect or redact allowed file contents before Claude receives them. Run `safepush scan` independently.
- Git, shell, searches, notebooks, subagents and MCP are denied, even when harmless. That is a deliberate limitation, not a general developer experience.
- A malicious or confused agent might introduce code that leaks secrets when a human later runs it. Human review and CI checks remain essential.
- File-system races and exotic paths/aliases are not comprehensively resolved. This is not evaluated as an adversarial sandbox.
- Hooks depend on the client faithfully enforcing the decision; this prototype has not been manually tested against a live Claude Code session.
- Use real OS separation for meaningful confidentiality: launch an agent in an isolated VM/container **without real credentials or sensitive mounts**, restrict outbound network, and let a trusted separate process/proxy make explicitly approved API calls with scoped credentials.
- Keep GitHub native secret scanning enabled and rotate credentials after suspected disclosure.

## Research motivation

- [The Framing Gap (August 2026)](https://arxiv.org/abs/2608.27092) demonstrates weaknesses of prompt-only defenses and the usefulness of destination restrictions and capability separation in a controlled benchmark.
- [AgentSecBench (May 2026)](https://arxiv.org/abs/2605.26269) distinguishes prompt policy descriptions from actual channel/capability enforcement.
- [GitInject (June 2026)](https://arxiv.org/abs/2606.09935) identifies structural flaws at agent/CI credential boundaries.
- [OpenAI Sandbox Security](https://developers.openai.com/api/docs/guides/agents-api/environments/security) recommends isolation, network restrictions, and keeping long-lived keys outside code-execution sandboxes.

Next step: build a **non-privileged isolated agent workspace** and a trusted secret broker, then test with synthetic canary values and realistic allowed workflows before claiming any protection of live keys.
