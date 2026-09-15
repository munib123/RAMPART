import { API, authHeaders } from '@/api/client';
import type { ApplyResult, CodeStatsRow, Exemplar, FixResponse, HistoryRow, RevertResult, VerifyResult } from '@/types';

export async function loadHistory(): Promise<HistoryRow[]> {
  const r = await fetch(API + '/api/scans', { headers: authHeaders() });
  if (!r.ok) throw new Error(`Request failed (${r.status})`);
  return (await r.json()) as HistoryRow[];
}

export async function loadCodebaseStats(): Promise<CodeStatsRow[]> {
  const r = await fetch(API + '/api/research/codebase', { headers: authHeaders() });
  if (!r.ok) throw new Error(`Request failed (${r.status})`);
  return (await r.json()) as CodeStatsRow[];
}

export async function generateFix(input: {
  code: string;
  cwe_id?: string;
  title?: string;
  message?: string;
  exemplars?: Exemplar[];
  scan_id?: string;
}): Promise<FixResponse> {
  const res = await fetch(API + '/api/fix', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(input),
  });
  return (await res.json()) as FixResponse;
}

export async function applyFix(p: {
  scan_id: string;
  path: string;
  start_line: number;
  end_line: number;
  fixed_code: string;
  original_code?: string;
}): Promise<ApplyResult> {
  const res = await fetch(API + '/api/fix/apply', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(p),
  });
  return (await res.json()) as ApplyResult;
}

export async function revertFix(p: { scan_id: string; target: string }): Promise<RevertResult> {
  const res = await fetch(API + '/api/fix/revert', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(p),
  });
  return (await res.json()) as RevertResult;
}

/** P8: re-verify a fix with the CPG. With fixed_code it previews on a scratch copy; without, it
 *  checks the live (already applied) tree against the snapshot. */
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
  const res = await fetch(API + '/api/fix/verify', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(p),
  });
  return (await res.json()) as VerifyResult;
}