import type { Evidence, Finding, Priority, RuleId } from './types.mjs';

/**
 * Evidence-first triage inspired by research on verified repair and
 * context-aware prioritization. This is NOT CVSS, reachability analysis,
 * proof of exploitation, or a reimplementation of those papers.
 * All strings are fixed descriptions, never copied from source contents.
 */
const observations: Record<RuleId, { evidence: Evidence; verify: string }> = {
  KNOWN_SECRET: {
    evidence: { source: 'pattern', summary: 'A known credential-format pattern matched; validity was not tested.' },
    verify: 'Inspect the referenced line locally. If genuine, revoke or rotate the credential at its provider.',
  },
  TRACKED_ENV_FILE: {
    evidence: { source: 'git-index', summary: 'Git index lists a non-template .env file; this does not prove it was pushed.' },
    verify: 'Review tracked paths using git ls-files --cached. If committed, rotate any exposed credentials.',
  },
  GENERIC_SECRET_ASSIGNMENT: {
    evidence: { source: 'heuristic', summary: 'A sensitive-looking assignment matched a heuristic; false positives are possible.' },
    verify: 'Check the variable and its intended use locally; do not paste its value into an issue.',
  },
  CLIENT_EXPOSED_SECRET_NAME: {
    evidence: { source: 'heuristic', summary: 'A browser-public variable name looks sensitive; its value was not assessed.' },
    verify: 'Check whether the value is intentionally public and inspect the actual client bundle if deployed.',
  },
  ENCODED_SECRET: {
    evidence: { source: 'pattern', summary: 'A known credential format matched after base64, hex or URL decoding; validity was not tested.' },
    verify: 'Decode the referenced value locally. Encoding does not protect a secret; rotate it if genuine.',
  },
  AGENT_CONFIG_SECRET: {
    evidence: { source: 'configuration', summary: 'An AI agent or MCP configuration file contains a literal credential-like value.' },
    verify: 'Move the value to an environment variable or the OS keychain and reference it from the config.',
  },
  AGENT_CONFIG_RISK: {
    evidence: { source: 'configuration', summary: 'A project-level agent setting can redirect credentials or run commands before review.' },
    verify: 'Confirm who added the setting and whether it is needed in a shared repository.',
  },
  HIDDEN_UNICODE: {
    evidence: { source: 'heuristic', summary: 'An agent instruction file contains invisible or bidirectional Unicode characters.' },
    verify: 'Inspect the line with a hex viewer or `cat -v`; legitimate instruction files rarely need these characters.',
  },
  ENV_GITIGNORE_MISSING: {
    evidence: { source: 'configuration', summary: 'Common .env ignore patterns were not detected; this is not a full Git ignore evaluation.' },
    verify: 'Review .gitignore and use git check-ignore for relevant paths; check tracked files separately.',
  },
};

export function addEvidence(finding: Finding, mode: 'staged' | 'workspace'): Finding {
  const observation = observations[finding.rule];
  let priority: Priority = 'review';
  if (finding.rule === 'TRACKED_ENV_FILE') priority = 'urgent';
  else if (finding.rule === 'KNOWN_SECRET' && finding.severity === 'high') priority = mode === 'staged' ? 'urgent' : 'high';
  return { ...finding, priority, evidence: { ...observation.evidence }, verify: observation.verify };
}

export function priorityOrder(priority: Priority | undefined): number {
  return priority === 'urgent' ? 0 : priority === 'high' ? 1 : 2;
}
