import { authHeaders, request } from '@/api/client';
import type {
  ApplyResult, CodeStatsRow, Exemplar, FixResponse, HistoryRow, RevertResult, VerifyResult,
} from '@/types';

// Long-running backend operations get their own ceilings. The default (30 s) is for reads.
const FIX_TIMEOUT_MS = 2 * 60 * 1000;          // one LLM generation
const APPLY_TIMEOUT_MS = 5 * 60 * 1000;        // snapshot the target + edit the file
const VERIFY_TIMEOUT_MS = 10 * 60 * 1000;      // rebuild the CPG on a scratch/live tree

export async function loadHistory(): Promise<HistoryRow[]> {
  return request<HistoryRow[]>('/api/scans', { headers: authHeaders() });
}

export async function loadCodebaseStats(): Promise<CodeStatsRow[]> {
  return request<CodeStatsRow[]>('/api/research/codebase', { headers: authHeaders() });
}

export async function generateFix(input: {
  code: string;
  cwe_id?: string;
  title?: string;
  message?: string;
  exemplars?: Exemplar[];
  scan_id?: string;
}): Promise<FixResponse> {
  return request<FixResponse>('/api/fix', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(input),
  }, { timeoutMs: FIX_TIMEOUT_MS, retries: 0 });
}

export async function applyFix(p: {
  scan_id: string;
  path: string;
  start_line: number;
  end_line: number;
  fixed_code: string;
  original_code?: string;
}): Promise<ApplyResult> {
  return request<ApplyResult>('/api/fix/apply', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(p),
  }, { timeoutMs: APPLY_TIMEOUT_MS, retries: 0 });
}

export async function revertFix(p: { scan_id: string; target: string }): Promise<RevertResult> {
  return request<RevertResult>('/api/fix/revert', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(p),
  }, { timeoutMs: APPLY_TIMEOUT_MS, retries: 0 });
}

/** P8: re-verify a fix with the CPG. With fixed_code it previews on a scratch copy; without, it
 *  checks the live (already applied) tree against the snapshot. A 401 is returned as a body so
 *  the panel can say "sign in again" instead of showing a generic failure. */
export async function verifyFix(p: {
  scan_id: string;
  path: string;
  function: string;
  rule_id: string;
  fixed_code?: string;
  start_line?: number;
  end_line?: number;
  original_code?: string;
}): Promise<VerifyResult> {
  return request<VerifyResult>('/api/fix/verify', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(p),
  }, { timeoutMs: VERIFY_TIMEOUT_MS, retries: 0, allowStatus: [401] });
}
