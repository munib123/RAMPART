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
  name?: string;
  is_admin: boolean;
  plan?: string;
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
  scan_id?: string;
  findings?: Finding[];
  /** plan_limit (402) passthrough, when set ok is false */
  code?: string;
  kind?: string;
  plan?: string;
  used?: number;
  limit?: number;
}

export interface HistoryRow {
  id: string;
  target: string;
  scanner: string;
  status: string;
  counts?: ScanCounts;
  verdict_summary?: Record<string, number>;
  scope?: Scope;
  created_at?: string;
}

export interface CodeStatsRow {
  platform?: string | null;
  scanner?: string;
  cwe_id?: string | null;
  severity?: string | null;
  verdict?: string | null;
  n?: number;
  avg_conf?: number | null;
}

export interface FixResponse {
  available: boolean;
  fixed_code?: string;
  summary?: string;
  error?: string;
  code?: string;
  kind?: string;
  plan?: string;
  used?: number;
  limit?: number;
  fixes_used?: number;
  fixes_limit?: number;
}

export interface FixState {
  loading?: boolean;
  fixed_code?: string;
  summary?: string;
  error?: boolean;
  view?: 'diff' | 'full';
  limit?: PlanLimitPayload | null;
  authRequired?: boolean;       // backend said the session is invalid/expired
  applied?: boolean;            // apply succeeded (file written)
  revertable?: boolean;         // a snapshot exists for this scan
  applyErr?: string;
}

export interface ApplyResult {
  ok: boolean;
  path?: string;
  start_line?: number;
  end_line?: number;
  original_code?: string;
  new_code?: string;
  code?: string;                // 'file_changed' | 'not_found'
  error?: string;
}

export interface RevertResult {
  ok: boolean;
  restored_from?: string;
  target?: string;
  code?: string;                // 'no_snapshot'
  error?: string;
}

/** Structured "plan limit reached" error from POST /api/scan or POST /api/fix. */
export interface PlanLimitPayload {
  code: string;          // 'plan_limit'
  kind: 'scan' | 'fix';
  plan?: string;
  used?: number;
  limit?: number;
}

/** Usage counters for one dimension (kept in sync with backend/app/config.py PLANS). */
export interface PlanUsage {
  used: number;
  limit: number;
}

/** Full plan + usage snapshot from GET /api/profile / GET /api/billing. */
export interface PlanInfo {
  plan: string;
  label?: string;
  scans: PlanUsage;
  fixes: PlanUsage;
  models?: { label?: string; note?: string };
}

/** Public plan catalog row from GET /api/billing/plans. */
export interface PlanRow {
  key: string;
  label: string;
  scans: number;
  fixes: number;
  price: string | number;
  note?: string;
}

export type DiffOp = 'ctx' | 'add' | 'del';
export interface DiffLine {
  t: DiffOp;
  s: string;
}
