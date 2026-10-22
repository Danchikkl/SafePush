const levels = { high: 'error', medium: 'warning' };
export function toSarif(result, version) {
    const rules = [...new Map(result.findings.map(f => [f.rule, f])).values()].map((f) => ({
        id: f.rule,
        name: f.rule.toLowerCase().replace(/_(.)/g, (_, c) => c.toUpperCase()),
        shortDescription: { text: f.title },
        fullDescription: { text: f.why },
        help: { text: f.fix + (f.verify ? '\n\nVerify: ' + f.verify : '') },
        properties: { tags: ['security', 'secrets'], 'security-severity': f.severity === 'high' ? '8.0' : '5.0' },
    }));
    return {
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        version: '2.1.0',
        runs: [{
                tool: { driver: { name: 'SafePush', version, informationUri: 'https://github.com/Danchikkl/SafePush', rules } },
                results: result.findings.map(f => ({
                    ruleId: f.rule,
                    level: levels[f.severity],
                    message: { text: f.title + '. ' + f.why },
                    locations: [{ physicalLocation: {
                                artifactLocation: { uri: f.file, uriBaseId: '%SRCROOT%' },
                                ...(f.line ? { region: { startLine: f.line } } : {}),
                            } }],
                    // Stable across unrelated edits so GitHub can track a finding between commits.
                    partialFingerprints: { 'safepush/v1': [f.rule, f.file, f.title].join('|') },
                })),
            }],
    };
}
