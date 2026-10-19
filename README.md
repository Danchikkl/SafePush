# 🛡️ SafePush

**Your AI built the app. SafePush checks the secrets before you share it.**

A free, local-first CLI that helps builders spot exposed credentials, unsafe browser environment variables, and common `.env` mistakes. Designed for Next.js, Vite, and people who build with AI coding assistants. No account, API key, AI subscription, or telemetry.

> **Status:** v0.1 experimental release candidate. This repository is ready to explore and contribute to, but the npm package is **not published yet**. A clean scan does **not** mean an app is secure.

## Try SafePush in 60 seconds

The built-in demo creates a temporary example project with **synthetic credentials only**, scans it, shows the findings, then shows a rescan after a simulated fix. It does **not** scan your private files.

```bash
git clone https://github.com/Danchikkl/SafePush.git
cd SafePush
npm ci --ignore-scripts
npm run demo
```

> Requires Node.js 22+ and npm. The CLI isn't published to npm yet.

## Scan your own project

```bash
npm run build

# Run the scanner on a local project you own or are authorized to check
node dist/cli.mjs scan /path/to/your-project

# Or check the exact staged Git contents
node dist/cli.mjs scan /path/to/your-project --staged
```

Want to help improve the next release? [Explore beginner-friendly issues](https://github.com/Danchikkl/SafePush/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22), read [CONTRIBUTING.md](CONTRIBUTING.md), or open an issue with an anonymized, **synthetic** reproduction. Never submit live keys.



Example result (synthetic values; credentials never shown):

```text
SafePush v0.1.0  ·  workspace  ·  3 file(s) scanned
Framework: Next.js
3 finding(s):

[HIGH] KNOWN_SECRET — src/config.ts:3
  Possible GitHub access token
  Why: A value resembling a credential is present in source code.
  Fix: If real, revoke/rotate it at the provider...

[HIGH] TRACKED_ENV_FILE — .env.production
  Environment file may enter source control
  ...

[MEDIUM] CLIENT_EXPOSED_SECRET_NAME — src/client.tsx:2
  Potentially sensitive browser-exposed environment variable
  ...
```

These paths and results are illustrative; the exact number of findings varies by project.

## Use SafePush with AI coding agents (MCP)

SafePush now has an **experimental local MCP server** that exposes one read-only tool, `safepush_scan`, to compatible agents such as Claude Code and Codex CLI. It uses the same scanner as the CLI; it does not upload source files, validate tokens, or modify your code. The agent can request a workspace or Git-index scan but cannot choose an arbitrary scan path.

After building the source checkout, register the server with your agent using an absolute path:

```bash
node /ABSOLUTE/PATH/TO/SafePush/dist/mcp.mjs --root /ABSOLUTE/PATH/TO/YOUR/PROJECT
```

This command is for MCP clients to launch; running it manually waits for protocol input. See **[Claude Code and Codex setup](docs/mcp.md)** for copyable client configuration, tests, and security boundaries.

**Important:** MCP makes the tool available, but does not guarantee an agent will call it. For an automatic pre-commit check, use the separate opt-in Git hook. A clean scan is not proof of security.

### Third-party MCP directory listing

SafePush has been [listed in the M8ven MCP Trust Index](https://m8ven.ai/mcp/danchikkl/safepush), a third-party directory of MCP servers. **A directory listing alone does not mean SafePush is certified, endorsed, security-audited, or a verified publisher.** Refer to M8ven's listing for its current assessment and verification status.

## Evidence-first triage (v0.2 preview)

Every finding now includes `priority` (`urgent`, `high`, or `review`), a **fixed, secret-free** `evidence` description, and manual `verify` guidance. Priorities help decide what to investigate first, **not** whether credentials are genuine or exploitable. JSON fields are additive; exit codes and severities are unchanged. See [design notes and limitations](docs/evidence-first-v0.2.md).

## Check pull requests with GitHub Actions

SafePush also includes an **experimental read-only composite GitHub Action** to scan a checked-out repository in CI, including pull requests. It runs the same scanner as the CLI and fails on high-severity findings by default. See **[GitHub Action setup and limitations](docs/github-action.md)** for a sample workflow and security guidance. The action will be usable from `@main` after its PR is merged; pin a reviewed commit SHA for production use.

## What works today

| Feature | What it does |
|---|---|
| `scan .` | Scan Git-tracked and untracked, non-ignored local text files |
| `scan --staged` | Scan **the Git index**, not potentially different working-tree contents |
| Known token patterns | Detect a small set of GitHub, OpenAI-style, Stripe, and Slack token formats |
| Generic credential heuristic | Flag some suspicious assignments, clearly labeled as uncertain |
| Client-exposed environment variables | Warn about sensitive names beginning with `NEXT_PUBLIC_`, `VITE_`, and `REACT_APP_` |
| Tracked `.env` detection | Warn if a non-template env file is tracked or staged |
| `init` | Add common `.env` patterns to `.gitignore` without replacing unrelated rules |
| `init --hook` | Opt-in pre-commit hook; never overwrite an existing one |
| `scan --json` | Structured report with **no matched secret values or code snippets** |
| Evidence-first triage | Deterministic priority, provenance and safe manual verification hints |
| `explain <RULE>` | Actionable, human-readable recovery guidance |
| `safepush-mcp` | Experimental read-only MCP stdio adapter for coding agents (build from source) |

**CLI exit codes:** `0` = no high findings; `1` = high findings (or any findings with `--strict`); `2` = CLI/scanning error. Medium warnings exit `0` by default.

## Installation for development

Requires **Node.js 22+** and Git for the Git-aware modes.

```bash
git clone https://github.com/Danchikkl/SafePush.git
cd safepush
npm install
npm run check
node dist/cli.mjs --help
```

You can run `npm link` from this checkout to make `safepush` available globally for your own local experiments. **Do not use `npx safepush` until the package is published under a verified name.** The `package.json` name (`safepush-dev`) is provisional and should be checked for availability before npm publication.

### Use it in your own project

```bash
# With a linked or eventually installed CLI:
safepush scan .
safepush init .
safepush scan . --strict

# Optional: pre-commit protection, requires SafePush installed locally
safepush init . --hook
```

`init` updates `.gitignore` but cannot undo an existing Git commit. `init --hook` modifies the local `.git/hooks` directory only after opt-in. It will **not** replace an existing hook and needs `./node_modules/.bin/safepush` in that repository to run successfully. Hooks can be bypassed; use CI and GitHub push protection too.

## How it works

```text
Project files / staged Git index
              │
              ▼
     SafePush local scanner
              │
   ┌──────────┼──────────────┐
   ▼          ▼              ▼
Token format  .env handling  Browser-exposed variable names
   └──────────┼──────────────┘
              ▼
      Finding + why + fix
              ▼
      Rescan after changes
```

The scan is entirely local: it has **no network requests**, no credential validation, no server, and no analytics. It never prints the matched secret, but **file paths and line numbers** are shown in reports. Treat reports as project-sensitive if paths are confidential.

## Important limitations

- Detection is **pattern/heuristic based**, incomplete, and can produce false positives or false negatives.
- Only the working tree / Git index is checked; **Git history, remote repositories, and deployed bundles are not scanned**.
- Ignored files, symlinks, large files (over 1 MB), binary files, and known generated outputs may be skipped.
- `NEXT_PUBLIC_` and `VITE_` aren't inherently insecure: **public IDs are often intentionally exposed**. For example, `VITE_APP_URL`, `VITE_SUPABASE_URL`, and `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` are not flagged by the current name-based rule. Names such as `VITE_ADMIN_PASSWORD` or `NEXT_PUBLIC_PRIVATE_KEY` are flagged. `NEXT_PUBLIC_FIREBASE_API_KEY` may be intentionally public yet still trigger a warning: the scanner cannot infer confidentiality from a variable name alone. Review the provider's guidance before acting.
- No full-code analysis, dynamic analysis, dependency audit, cloud scan, or automatic rotation.
- GitHub's secret scanning and push protection are complementary and should remain enabled.
- Windows CI tests use Node.js 22. Windows symlink tests skip only when the runner lacks the privilege to create symlinks; this is not a claim that all Windows filesystem edge cases are covered.
- If a real key was pushed, **revoke it even if you subsequently delete the source line**.

For broader scanning, consider [Gitleaks](https://github.com/gitleaks/gitleaks), [Secretlint](https://github.com/secretlint/secretlint), and [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning). We aim to complement, not replace, those tools.

## Why contribute?

SafePush is trying to solve a small but important user problem: **new developers often see a security warning without understanding the repair steps**. Our emphasis is approachable prevention and guided remediation. Please don't add a detector unless you can explain what to do when it fires.

See [CONTRIBUTING.md](CONTRIBUTING.md) and the issue templates. Especially welcome: negative tests, false-positive reductions, better instructions, translations, and safe fixes requiring user approval.

## Roadmap

- **v0.1:** Local scans, Git-index scans, understandable findings, opt-in hook (implemented).
- **v0.2:** Improved framework-specific remediation, safe preview of suggested edits, better ignore-file handling.
- **v0.3:** GitHub Action (experimental implementation), broader test matrix and benchmarks on opt-in / synthetic projects.
- **Agent integration:** Experimental local MCP server for Claude Code / Codex (in main). Agent hooks and broader client compatibility remain future work.
- **Later:** Localization and contributor-contributed rule library.

See [docs/launch-playbook.md](docs/launch-playbook.md) for a practical public launch plan.

## Safe disclosure and license

Do not scan repositories you do not own without authorization. Do not validate, collect, or email anyone else's credentials. If you discover an issue in this project, follow [SECURITY.md](SECURITY.md) and use private reporting.

MIT License. © 2026 SafePush contributors.