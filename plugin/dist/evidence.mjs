/**
 * Evidence-first triage inspired by research on verified repair and
 * context-aware prioritization. This is NOT CVSS, reachability analysis,
 * proof of exploitation, or a reimplementation of those papers.
 * All strings are fixed descriptions, never copied from source contents.
 */
const observations = {
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
    ENV_GITIGNORE_MISSING: {
        evidence: { source: 'configuration', summary: 'Common .env ignore patterns were not detected; this is not a full Git ignore evaluation.' },
        verify: 'Review .gitignore and use git check-ignore for relevant paths; check tracked files separately.',
    },
};
export function addEvidence(finding, mode) {
    const observation = observations[finding.rule];
    let priority = 'review';
    if (finding.rule === 'TRACKED_ENV_FILE')
        priority = 'urgent';
    else if (finding.rule === 'KNOWN_SECRET' && finding.severity === 'high')
        priority = mode === 'staged' ? 'urgent' : 'high';
    return { ...finding, priority, evidence: { ...observation.evidence }, verify: observation.verify };
}
export function priorityOrder(priority) {
    return priority === 'urgent' ? 0 : priority === 'high' ? 1 : 2;
}
