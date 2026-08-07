import { API, authHeaders, type ScanPayload } from '@/api/client';
import type { ScanReport } from '@/types';

export async function runScan(payload: ScanPayload, signal?: AbortSignal): Promise<ScanReport> {
  const res = await fetch(API + '/api/scan', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(payload),
    signal,
  });
  return (await res.json()) as ScanReport;
}

export async function browse(): Promise<{ path?: string }> {
  try {
    return (await (await fetch(API + '/api/browse')).json()) as { path?: string };
  } catch {
    return {};
  }
}