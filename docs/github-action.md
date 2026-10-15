# SafePush GitHub Action (experimental)

SafePush can run as a **read-only GitHub Actions check** on pull requests. It runs the existing CLI scanner on the checked-out project and fails the job if it finds a high-severity issue (or any issue with `strict: 'true'`).

> **Status:** The action is available from the repository once this PR is merged. The npm package is not published. This is an early integration, not a complete security audit.

## Quick start

Create `.github/workflows/safepush.yml` **in your own repository**:

```yaml
name: SafePush
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - name: Check for exposed credentials
        uses: Danchikkl/SafePush@main
        with:
          strict: 'false'
```

**For production:** pin `Danchikkl/SafePush` to a reviewed full commit SHA (or a versioned release if you accept moving tags). `@main` is shown only to simplify early testing and changes over time.

## Behavior

- Runs the local SafePush scanner on the checked-out `GITHUB_WORKSPACE`.
- Does **not** send source files or credentials to a SafePush service, validate credentials against provider APIs, or modify your project.
- Logs rule IDs, paths, line numbers, and remediation instructions, **not matched credential values**. Paths may still reveal private project structure.
- Uses Node.js 22 and installs the action's build dependencies with `npm ci --ignore-scripts` before compiling; the runner therefore needs access to npm and GitHub.
- Exit code `1` fails the job for high-severity findings; `strict: 'true'` also fails on medium-severity findings. Scan errors exit `2` and fail the job.
- Unlike `scan --staged`, the action scans the **checked-out workspace**, not just staged changes. It may flag pre-existing issues; use it as a repository-wide check.
- Current scanner intentionally skips ignored files, binary files, common generated extensions, and oversized files. It reports some skipped files but does not fail all workspace scans for skips. A passing check is **not** proof of complete coverage.
- GitHub's native secret scanning and push protection remain valuable complementary protections.

## Security notes

Use `pull_request`, **not `pull_request_target`**, when checking code from contributors. Keep `permissions: contents: read` and avoid exposing deployment or production credentials to scan jobs. Do not paste actual secrets into bug reports. If a key was already committed, revoke/rotate it; deleting the file does not remove Git history.

## Local development

```bash
npm ci --ignore-scripts
npm run check
node dist/cli.mjs scan /path/to/your-project
```

The action is a thin wrapper around the existing scanner. It does not yet produce SARIF, PR annotations, or auto-fixes. Those should be considered only after validating scanner accuracy and safety.
