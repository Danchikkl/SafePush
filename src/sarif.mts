/**
 * SARIF 2.1.0 output (`safepush scan --sarif`), the format GitHub code scanning, VS Code's
 * SARIF viewer and most security dashboards ingest. With the GitHub Action, findings then
 * appear as annotations on the pull request diff and in the repository's Security tab.
 * Contains rule ids, messages, paths and lines only: never matched values or snippets.
 */
import type { Finding, ScanResult } from './types.mjs';

const levels = { high: 'error', medium: 'warning' } as const;

export function toSarif(result: ScanResult, version: string): object {
  const rules = [...new Map(result.findings.map(f => [f.rule, f])).values()].map((f: Finding) => ({
    id: f.rule,
    name: f.rule.toLowerCase().replace(/_(.)/g, (_, c: string) => c.toUpperCase()),
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
