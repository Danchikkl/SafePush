export type Severity = 'high' | 'medium';
export type Priority = 'urgent' | 'high' | 'review';
export type EvidenceSource = 'pattern' | 'git-index' | 'heuristic' | 'configuration';
export interface Evidence { source: EvidenceSource; summary: string; }
export type RuleId =
  | 'KNOWN_SECRET'
  | 'GENERIC_SECRET_ASSIGNMENT'
  | 'TRACKED_ENV_FILE'
  | 'CLIENT_EXPOSED_SECRET_NAME'
  | 'ENV_GITIGNORE_MISSING'
  | 'ENCODED_SECRET'
  | 'AGENT_CONFIG_SECRET'
  | 'AGENT_CONFIG_RISK'
  | 'HIDDEN_UNICODE';

export interface Finding {
  rule: RuleId;
  severity: Severity;
  file: string;
  line?: number;
  title: string;
  why: string;
  fix: string;
  /** Triage guidance, not an exploitability score. Added by the scanner. */
  priority?: Priority;
  /** Static, secret-free explanation of what was observed. */
  evidence?: Evidence;
  /** Safe manual verification step; never validates credentials remotely. */
  verify?: string;
}
export interface ScanOptions {
  root: string;
  staged?: boolean;
}
export interface ScanResult {
  root: string;
  filesScanned: number;
  mode: 'staged' | 'workspace';
  frameworks: string[];
  findings: Finding[];
  skippedLargeOrBinary: number;
}
