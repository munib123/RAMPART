import type { ScanReport } from '@/types';

// The last successful report, so a refresh on /report restores the table instead of showing
// "No report loaded". sessionStorage is per-tab and cleared on sign-out; the payload is capped
// so a huge report cannot exhaust the quota (it is simply not persisted).
export const REPORT_KEY = 'rampart.report';
const MAX_CHARS = 1_500_000;   // ~1.5 MB of UTF-16 code units

export interface PersistedReport {
  report: ScanReport;
  path?: string;
  savedAt: number;
}

export function saveReport(report: ScanReport, path?: string): void {
  if (!report || !report.ok) return;
  try {
    const payload: PersistedReport = {
      report,
      path: path || report.target || '',
      savedAt: Date.now(),
    };
    const text = JSON.stringify(payload);
    if (text.length > MAX_CHARS) {
      sessionStorage.removeItem(REPORT_KEY);
      return;
    }
    sessionStorage.setItem(REPORT_KEY, text);
  } catch {
    /* quota exceeded or storage disabled: fail silently, as designed */
  }
}

export function loadReport(): PersistedReport | null {
  try {
    const raw = sessionStorage.getItem(REPORT_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as PersistedReport;
    if (!parsed || typeof parsed !== 'object' || !parsed.report) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function clearReport(): void {
  try {
    sessionStorage.removeItem(REPORT_KEY);
  } catch {
    /* ignore */
  }
}
