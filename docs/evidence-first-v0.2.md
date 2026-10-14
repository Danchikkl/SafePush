# Evidence-first triage (v0.2 preview)

SafePush adds **secret-free evidence metadata**, **manual verification guidance**, and **deterministic priority ordering** to existing findings. This is a small engineering adaptation of research ideas, **not** a reproduction or validation of the papers.

## Research inspiration

- [ToFu: Exploiting and Fuzzing the LLM-Orchestrator-Tool Trust Boundary](https://arxiv.org/abs/2610.13651) (9 October 2026): never assume tool metadata or untrusted inputs are sufficient guarantees. We retain local Git-index checks and add tests using adversarial filenames; no MCP fuzzing engine is implemented.
- [EviRepair: Evidence-Driven Agents for Reliable Vulnerability Repair](https://arxiv.org/abs/2610.13491) (9 October 2026): prefer reviewed evidence before proposing repairs. Our reports now distinguish token-pattern matches, Git-index observations, configuration checks and heuristics; no agent-based automatic repair is implemented.
- [CAPE: Context-Aware Prioritization Engine for Vulnerability Scoring and Management](https://arxiv.org/abs/2610.13071) (9 October 2026): prioritization should depend on context. SafePush uses a simple staged-vs-workspace rule; it does **not** compute CVSS, exploitability, reachability, or CAPE scores.

These are new arXiv preprints, not independently validated production guarantees.

## Output contract

Each finding retains the existing `rule`, `severity`, `file`, `line`, `title`, `why`, and `fix` fields, and adds:

| Field | Meaning |
|---|---|
| `priority` | `urgent`, `high`, or `review`: **triage hint**, not exploitability or confirmed exposure |
| `evidence.source` | `pattern`, `git-index`, `heuristic`, or `configuration` |
| `evidence.summary` | Fixed, non-sensitive description of the observed condition |
| `verify` | Manual local verification instructions, never a credential-validation request |

Existing exit codes and severity meanings are unchanged. The new fields are **additive**, but JSON consumers should not assume an unchanging sort order.

## Triage logic

1. Non-template `.env` files in the Git index are `urgent`, even if unchanged during a staged scan. This does not prove that the file was pushed to a remote.
2. A known credential-format match in staged changes is `urgent`; in a workspace scan it is `high`. This does not prove the token is genuine.
3. Generic assignments, browser-public names, and missing common ignore patterns are `review`, because they are heuristic/configuration signals.

Within a priority tier, results are sorted by path and line number.

## Privacy and threat model

- No network requests, telemetry, credential validation, or AI model calls.
- Evidence descriptions and verification steps are **fixed strings**; matched values and code snippets are not copied into them.
- Paths are still included (sanitized in CLI/JSON), so reports may expose project structure.
- Existing limitations remain: partial pattern coverage, false positives/negatives, ignored/generated/large files, Git history not scanned, and filesystem race conditions.
- Tests include staged/workspace priority, Git-index provenance, redaction and malicious-looking filenames. The test suite is not a formal security audit.

## Future work (not shipped here)

- Opt-in rule-specific fuzz harnesses and cross-platform test matrices.
- User-approved remediation previews with before/after checks.
- Validated context signals from build artifacts or dependency graphs, rather than guessed reachability.
