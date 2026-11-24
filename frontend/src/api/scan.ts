import { authHeaders, request, type ScanPayload } from '@/api/client';
import type { ScanReport } from '@/types';

// A scan can queue behind another one (RAMPART_SCAN_QUEUE_TIMEOUT) and then run for minutes;
// give it a generous ceiling so a slow repo is not mistaken for a dead backend.
export const SCAN_TIMEOUT_MS = 15 * 60 * 1000;

export async function runScan(payload: ScanPayload, signal?: AbortSignal): Promise<ScanReport> {
  return request<ScanReport>('/api/scan', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(payload),
  }, {
    timeoutMs: SCAN_TIMEOUT_MS,
    retries: 0,
    signal,
    // A 402 carries the structured plan-limit upsell; return it rather than throwing.
    allowStatus: [402],
  });
}

export async function browse(): Promise<{ path?: string; error?: string }> {
  try {
    return await request<{ path?: string; error?: string }>('/api/browse', {}, {
      timeoutMs: 5 * 60 * 1000,     // the native folder dialog waits for the user
      retries: 0,
    });
  } catch {
    return {};
  }
}
