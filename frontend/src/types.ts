export interface HealthScanner {
  available: boolean;
  note?: string;
}

export interface CollectionInfo {
  collection: string;
  vectors: number | null;
}

export interface Health {
  ok: boolean;
  llm_enabled: boolean;
  model: string | null;
  scanner: string;
  scanners: { semgrep: HealthScanner; bandit: HealthScanner };
  default_target: string;
  db_enabled: boolean;
  collections: CollectionInfo[];
}

export interface User {
  id: string;
  email: string;
  is_admin: boolean;
  created_at?: string;
}

export interface AuthResponse {
  user: User;
  token: string;
}

export interface Scope {
  platform?: string;
  stack?: string[];
  priorities?: string[];
}

export interface Exemplar {
  title?: string;
  cwe_id?: string;
  cwe_name?: string;
  severity?: string;
  source?: string;
  section_type?: string;
  url?: string;
  sim?: number;
  text?: string;
}

export interface Slice {
  code?: string;
  start_line?: number;
  end_line?: number;
  name?: string;
}

export interface Verdict {
  available?: boolean;
  verdict?: string;
  confidence?: number;
  cwe?: string;
  vuln_class?: string;
  explanation?: string;
  fix_suggestion?: string;
}

export interface Finding {
  tool?: string;
  rule_id?: string;
  title?: string;
  path?: string;
  line?: number;
  end_line?: number;
  severity?: string;
  confidence?: string;
  cwe_id?: string;
  message?: string;
  slice?: Slice;
  exemplars?: Exemplar[];
  verdict?: Verdict;
}

export interface ScanCounts {
  total?: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
}

export interface ScanReport {
  ok: boolean;
  target?: string;
  scanner?: string;
  scope?: Scope;
  llm?: { enabled: boolean; model: string | null };
  counts?: ScanCounts;
  elapsed_s?: number;
  error?: string;
  findings?: Finding[];
}

export interface HistoryRow {
  id: string;
  target: string;
  scanner: string;
  status: string;
  counts?: ScanCounts;
  verdict_summary?: Record<string, number>;
  created_at?: string;
}

export interface FixResponse {
  available: boolean;
  fixed_code?: string;
  summary?: string;
  error?: string;
}

export interface FixState {
  loading?: boolean;
  fixed_code?: string;
  summary?: string;
  error?: boolean;
  view?: 'diff' | 'full';
}

export type DiffOp = 'ctx' | 'add' | 'del';
export interface DiffLine {
  t: DiffOp;
  s: string;
}
