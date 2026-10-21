# SafePush MCP server (experimental)

SafePush includes a **local, read-only MCP stdio server** so compatible coding agents can call the same scanner as the CLI. No cloud endpoint, accounts, new npm dependencies, telemetry, or credential validation.

**Status:** Experimental, source checkout only; not published to npm. MCP makes a tool available to an agent but **does not guarantee automatic checks**. For deterministic pre-commit checks, also use the opt-in Git hook.

## Build

Requires Node.js 22+, npm, and Git for staged scans.

    git clone https://github.com/Danchikkl/SafePush.git
    cd SafePush
    npm ci --ignore-scripts
    npm run build

The server command is:

    node /ABSOLUTE/PATH/TO/SafePush/dist/mcp.mjs --root /ABSOLUTE/PATH/TO/YOUR/PROJECT

Use real **absolute paths**. On Windows, use full Windows paths. The server waits for JSON-RPC messages on stdin; normally your agent launches it.

The project root is pinned at startup; an agent cannot pass another root through the tool. If the path is inside a Git repository, it must be the **repository root**, because Git scans otherwise operate on the parent repository.

## Claude Code

The easiest option is the [SafePush plugin](claude-code-hooks.md#as-a-plugin-recommended), which adds this MCP server together with the hook. Without `--root`, the server scans the Git repository that contains the directory it is started from.

To register only the MCP server, from the project to scan:

    claude mcp add --transport stdio safepush -- node /ABSOLUTE/PATH/TO/SafePush/dist/mcp.mjs --root /ABSOLUTE/PATH/TO/YOUR/PROJECT
    claude mcp list

Alternatively, project-scoped .mcp.json:

    {
      "mcpServers": {
        "safepush": {
          "type": "stdio",
          "command": "node",
          "args": [
            "/ABSOLUTE/PATH/TO/SafePush/dist/mcp.mjs",
            "--root",
            "/ABSOLUTE/PATH/TO/YOUR/PROJECT"
          ]
        }
      }
    }

Review MCP configuration before trusting it. Do not commit private paths or credentials to shared repositories.

## Codex CLI

    codex mcp add safepush -- node /ABSOLUTE/PATH/TO/SafePush/dist/mcp.mjs --root /ABSOLUTE/PATH/TO/YOUR/PROJECT
    codex mcp list

Or add to ~/.codex/config.toml:

    [mcp_servers.safepush]
    command = "node"
    args = ["/ABSOLUTE/PATH/TO/SafePush/dist/mcp.mjs", "--root", "/ABSOLUTE/PATH/TO/YOUR/PROJECT"]

Optional AGENTS.md instruction: "Before committing, call the safepush_scan MCP tool with staged=true. Treat findings as warnings, not proof of exposure. Do not reveal credentials in chat." Instructions influence agent behavior but do not guarantee a tool call.

## Tool contract

- Transport: newline-delimited JSON-RPC 2.0 over stdio. Stdout contains **only protocol messages**.
- Protocol subset: legacy initialization (2025-06-18 and 2025-11-25) and modern stateless discovery (2026-07-28), with ping, tools/list and tools/call. This is not a complete general-purpose MCP SDK.
- Tool: safepush_scan
- Arguments: optional boolean staged (default false). Staged=true scans the Git index.
- Response: JSON text and structuredContent with mode, filesScanned, findings, totalFindings, truncated, skippedLargeOrBinary and disclaimer.
- Findings capped at **100** per tool response. If truncated is true, run the CLI for the full report.
- Scan failures return isError=true, never a clean result.
- No automatic edits, auto-fixes, or token validity checks.

## Security boundaries

1. The scanner reads project files locally. Findings include **paths and line numbers** which may expose project structure to the connected agent.
2. Matched secret values and code snippets are not intentionally returned. Token-shaped paths and control characters are sanitized, but other path data may still be sensitive.
3. No arbitrary path arguments, agent-requested shell execution, remote scanning, or credential validation.
4. The server does not restrict other filesystem permissions the agent might have. An agent may read files independently.
5. A clean scan is not a security audit. The scanner may miss secrets, skip ignored/binary/large files, and does not scan Git history.
6. Do not run with elevated permissions.

## Test

    npm run check

Tests cover legacy and modern protocols, Git index vs worktree, pinned-root enforcement, redaction, malformed arguments, and incomplete staged scans.

## Later

- Deterministic checks for other agents. For Claude Code, see the opt-in [hook adapter](claude-code-hooks.md).
- Separate confidence heuristics for obvious synthetic tokens, **without silently suppressing known credential patterns**.
- Additional interoperability and conformance testing against MCP SDK clients.
