import { useCallback, useEffect, useRef, useState } from 'react';
import { runScan } from '@/api/scan';
import { announce } from '@/api/client';
import type { ScanReport } from '@/types';
import { STAGE_META, buildStageRows, type StageRow } from '@/hooks/scanMeta';

export interface UseScanOpts {
  path: string;
  scanner: string;
  scope: Record<string, unknown>;
  model?: string | null;
  activeScanner?: string;
}

export interface UseScanResult {
  elapsedMs: number;
  percent: number;
  running: boolean;
  longNote: boolean;
  report: ScanReport | null;
  error: string | null;
  stageRows: StageRow[];
  start: () => void;
  cancel: () => void;
}

// The whole scan is one backend call, so per-stage timing is not known from the server.
// We animate Gain by FRACTIONS of a display window instead of absolute-ms thresholds:
// stage 1 (Scan) up to FRAC_T1, stage 2 (Ground) up to FRAC_T2, then Verify.
const FRAC_T1 = 0.30;
const FRAC_T2 = 0.70;
// Minimum on-screen sweep so even a sub-second scan visibly fills the bar / runs the
// timer through all three stages before the report is shown.
const MIN_DISPLAY_MS = 5200;
const DONE_ELAPSED = 400000; // sentinel: forces 100% + all stages done

export function useScan({ path, scanner, scope, model, activeScanner }: UseScanOpts): UseScanResult {
  const [elapsedMs, setElapsedMs] = useState(0);
  const [running, setRunning] = useState(false);
  const [longNote, setLongNote] = useState(false);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const ctrlRef = useRef<AbortController | null>(null);
  const t0Ref = useRef(0);
  const timerRef = useRef<number | null>(null);
  const stageTimesRef = useRef<(number | null)[]>([null, null, null]);
  const seenStageRef = useRef(0); // tracks the highest-introduced stage in the timer
  const pendingRef = useRef<ScanReport | null>(null); // backing result awaiting the sweep
  const commitAtRef = useRef(0); // elapsed threshold at which to show the result

  useEffect(() => () => {
    if (timerRef.current) window.clearInterval(timerRef.current);
    ctrlRef.current?.abort();
  }, []);

  // Progress is a fraction of the display window; the clock still shows real elapsed ms.
  const frac = Math.min(1, elapsedMs / MIN_DISPLAY_MS);
  const completed = elapsedMs >= DONE_ELAPSED;
  const stage =
    completed ? 3 :
    frac < FRAC_T1 ? 0 :
    frac < FRAC_T2 ? 1 : 2;
  const percent = completed ? 100 : Math.min(96, frac * 100);
  const stageRows: StageRow[] = buildStageRows(
    stage, Math.floor(elapsedMs / 900), model ?? null, activeScanner, stageTimesRef.current, completed,
  );

  const start = useCallback(() => {
    ctrlRef.current?.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;
    t0Ref.current = performance.now();
    stageTimesRef.current = [null, null, null];
    seenStageRef.current = 0;
    pendingRef.current = null;
    commitAtRef.current = MIN_DISPLAY_MS;
    setElapsedMs(0);
    setLongNote(false);
    setReport(null);
    setError(null);
    setRunning(true);

    timerRef.current = window.setInterval(() => {
      const el = performance.now() - t0Ref.current;
      setElapsedMs(el);
      if (el > 150000) setLongNote(true);

      const f = Math.min(1, el / MIN_DISPLAY_MS);
      const s = el >= DONE_ELAPSED ? 3 : f < FRAC_T1 ? 0 : f < FRAC_T2 ? 1 : 2;
      const times = stageTimesRef.current;
      if (s > 0 && times[0] == null) times[0] = el;
      if (s > 1 && times[1] == null) times[1] = el;
      if (s !== seenStageRef.current) {
        if (s < seenStageRef.current || s > 2) return;
        announce(STAGE_META[s].name + ' stage started');
        seenStageRef.current = s;
      }

      // Reveal the result once the backend has returned AND the sweep window is satisfied.
      if (pendingRef.current && el >= commitAtRef.current) {
        const res = pendingRef.current;
        pendingRef.current = null;
        if (timerRef.current) { window.clearInterval(timerRef.current); timerRef.current = null; }
        for (let i = 0; i < 3; i++) if (times[i] == null) times[i] = el;
        setElapsedMs(DONE_ELAPSED);
        setReport(res);
        setRunning(false);
      }
    }, 110);

    (async () => {
      try {
        const res = await runScan({ path, scanner, scope }, ctrl.signal);
        if (ctrl.signal.aborted) return;
        // Hold the report; it is revealed once the sweep has played out.
        pendingRef.current = res;
        commitAtRef.current = Math.max(MIN_DISPLAY_MS, performance.now() - t0Ref.current);
      } catch (e) {
        if ((e as Error).name !== 'AbortError') {
          const msg = (e as Error).message || 'Scan failed';
          const fail: ScanReport = { ok: false, error: msg };
          pendingRef.current = fail;
          commitAtRef.current = Math.max(MIN_DISPLAY_MS, performance.now() - t0Ref.current);
          setError(msg);
        }
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, scanner, scope]);

  const cancel = useCallback(() => {
    pendingRef.current = null;
    ctrlRef.current?.abort();
    if (timerRef.current) { window.clearInterval(timerRef.current); timerRef.current = null; }
    setRunning(false);
  }, []);

  return { elapsedMs, percent, running, longNote, report, error, stageRows, start, cancel };
}