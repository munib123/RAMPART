import { API, authHeaders, type ScanPayload } from '@/api/client';
import type { PlanLimitPayload, ScanReport } from '@/types';

export async function runScan(payload: ScanPayload, signal?: AbortSignal): Promise<ScanReport> {
  const res = await fetch(API + '/api/scan', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(payload),
    signal,
  });
  if (res.status === 402) {
    // Structured plan-limit response: pass it through so the UI can show an upsell.
    try {
      const j = (await res.json()) as ScanReport & PlanLimitPayload;
      return j as ScanReport;
    } catch {
      /* fall through to generic handling */
    }
  }
  return (await res.json()) as ScanReport;
}

export async function browse(): Promise<{ path?: string }> {
  try {
    return (await (await fetch(API + '/api/browse')).json()) as { path?: string };
  } catch {
    return {};
  }
}