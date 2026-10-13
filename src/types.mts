export type Severity = 'high' | 'medium';
export type RuleId =
  | 'KNOWN_SECRET'
  | 'GENERIC_SECRET_ASSIGNMENT'
  | 'TRACKED_ENV_FILE'
  | 'CLIENT_EXPOSED_SECRET_NAME'
  | 'ENV_GITIGNORE_MISSING';

export interface Finding {
  rule: RuleId;
  severity: Severity;
  file: string;
  line?: number;
  title: string;
  why: string;
  fix: string;
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
