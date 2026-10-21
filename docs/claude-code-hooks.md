# Claude Code hooks (experimental, opt-in)

The [MCP server](mcp.md) gives an agent a scan tool, but the agent decides whether to call it. A **Claude Code hook** runs on every matching tool call, without relying on the model to remember. SafePush ships an adapter for this: `safepush hook claude`.

**Nothing is enabled automatically.** SafePush never edits your Claude Code settings. The hook only runs if you add it yourself, as shown below.

## What it checks

The hook handles `PreToolUse` events, i.e. **before** Claude runs a tool:

| Agent action | SafePush response |
|---|---|
| `Write` / `Edit` / `MultiEdit` / `NotebookEdit` with a known credential format (GitHub, OpenAI, Anthropic, Stripe, Slack, AWS key ID, private key block) in a normal source file | **deny**: the write is blocked and Claude is told to use an environment variable instead |
| Same, but only a heuristic finding (e.g. `OPENAI_API_KEY = "…"`, password in a DB URL, sensitive `NEXT_PUBLIC_` name, Google API key) | **ask**: you see the reason and decide |
| Writing a real `.env` file that Git **ignores** | allowed: that is where secrets belong |
| Writing a `.env` file that Git would **not** ignore | **ask** |
| Writing a sensitive `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` variable to any `.env` file | **ask** |
| `git commit` when the staged changes have high-severity findings (`git commit -a` also checks modified tracked files) | **deny** |
| `git commit --no-verify` / `-n` | **deny**: agents must not skip Git hooks |
| Read of a real .env file, private-key file (*.pem, *.key, *.p12, *.pfx, id_rsa, id_ed25519) or common credential file (.npmrc, .netrc, .pypirc, .aws/credentials, secrets.json) | **deny**: the agent is not given the file contents |
| Grep whose explicit path or glob directly targets one of those files | **deny** |
| Bash command that explicitly references one of those files with a read/copy command (e.g. cat .env, git show HEAD:.env) | **deny** |
| A shell command that contains a known credential format | **ask** |
| Anything else | no output; Claude Code's normal permission flow continues |

Reasons shown to Claude and to you contain rule names, file paths and line numbers, **never the matched value**.

## Enable it

1. Build SafePush from source (see the README) and note the absolute path to `dist/cli.mjs`.
2. Add this to **one** Claude Code settings file you control, for example your project's `.claude/settings.local.json` (personal, not committed) or `~/.claude/settings.json` (all projects):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash",
        "hooks": [
          {
            "type": "command",
            "command": "node /ABSOLUTE/PATH/TO/SafePush/dist/cli.mjs hook claude"
          }
        ]
      }
    ]
  }
}
```

3. Restart Claude Code, or review the hook with the `/hooks` command.

To try it without Claude Code, pipe a synthetic event:

```bash
echo '{"hook_event_name":"PreToolUse","cwd":"'"$PWD"'","tool_name":"Bash","tool_input":{"command":"git commit --no-verify -m test"}}' \
  | node dist/cli.mjs hook claude
```

To disable it, remove the entry from your settings.

## Limitations

- **Patterns and heuristics only.** The same detectors as `safepush scan`; secrets in unknown formats will be missed.
- **Only explicit paths and command text.** A broad search of the workspace may still read hidden files depending on the tool, and arbitrary scripts, aliases, encoded paths, symlinks, subprocesses, or a git push of commits made earlier can bypass textual checks. This hook is not an OS sandbox and cannot guarantee that the agent never sees a secret. Keep the Git pre-commit hook, CI and GitHub push protection.
- **`git commit` detection is textual.** Commands assembled indirectly (aliases, scripts, `sh -c "$VAR"`) are not recognised. The repository is taken from `-C <dir>` or the session's working directory; a preceding `cd other && git commit` is checked against the working directory.
- **Fails closed on bad input.** Malformed or oversized hook input exits with status 2, which blocks the tool call. This is safer for secrets but can interrupt work if Claude Code changes its event format; check the hook after upgrading Claude Code.
- **`ask` decisions are only as good as your review.** If you approve, the action proceeds.
- A clean result is not a security audit.
