import { API, authHeaders } from '@/api/client';
import type { Exemplar, FixResponse, HistoryRow } from '@/types';

export async function loadHistory(): Promise<HistoryRow[]> {
  const r = await fetch(API + '/api/scans', { headers: authHeaders() });
  if (!r.ok) throw new Error(`Request failed (${r.status})`);
  return (await r.json()) as HistoryRow[];
}

export async function generateFix(input: {
  code: string;
  cwe_id?: string;
  title?: string;
  message?: string;
  exemplars?: Exemplar[];
}): Promise<FixResponse> {
  const res = await fetch(API + '/api/fix', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  return (await res.json()) as FixResponse;
}