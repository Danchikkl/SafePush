# Security audit — v0.1 experimental

## Local checks
- TypeScript compiled, and 20 local regression tests passed on the source build used as the project starting point.
- Known token values are not included in normal/JSON findings.
- Symlinks leading outside the scanned root are excluded from workspace reads.
- Staged Git scans use index objects, fail on eligible oversized/binary content, and report unchanged tracked .env files.
- .gitignore writes use no-follow + append-only protections where supported; custom hook directories are not modified automatically.
- GitHub Actions is configured for read-only permissions and pinned action versions.

## Important limitations and release blockers
- Detection is deliberately incomplete. A clean scan is **not proof of security**.
- Git history, network services, deployed bundles, packages, most secrets and many binary or large files are not scanned.
- Filename redaction only covers known token shapes; do not share reports publicly without review.
- Some filesystem race conditions and platform differences remain.
- Complex ignore patterns are handled heuristically.
- This is not a third-party penetration test or comprehensive code audit.
- A lockfile was generated on GitHub's CI runner and committed. Both npm ci and npm audit must remain green before npm publication.
- CI runs on GitHub were verified on Node.js 20/22 prior to the reproducible-install update. Current Node.js 22/24 runs still need confirmation.

## Release checklist
1. Generate and review package-lock.json from the npm registry; then use npm ci in CI.
2. Run npm audit and test on Linux, macOS and Windows / Node 20 and 22.
3. Enable private vulnerability reporting, Dependabot, and protected main.
4. Validate npm package ownership and provenance before recommending any npx invocation.
5. Benchmark false positives and false negatives with synthetic and opt-in datasets.

Never include real credentials in tests or bug reports.
