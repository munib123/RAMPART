import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { health } from '@/api/health';
import type { Health } from '@/types';

const HealthContext = createContext<Health | null>(null);
const RefreshContext = createContext<() => void>(() => {});

// The Joern sidecar comes up 15-40 s after the backend does; while /api/health says
// "running but not ready" we poll so the Setup page's CPG note flips to "ready" on its own.
const SIDECAR_POLL_MS = 5000;
const SIDECAR_POLL_MAX = 24;          // 2 min, then stop and wait for the next focus/refresh
// While the backend is cold (or stopped), retry with exponential backoff instead of nudging it
// every few seconds. The first probe can take ~20 s on a cold ONNX/scan-tool start.
const RETRY_BASE_MS = 2000;
const RETRY_MAX_MS = 30000;

export function HealthProvider({ children }: { children: ReactNode }) {
  const [data, setData] = useState<Health | null>(null);
  const alive = useRef(true);
  const inflight = useRef<Promise<Health | null> | null>(null);
  const controller = useRef<AbortController | null>(null);
  const retryTimer = useRef<number | null>(null);
  const polls = useRef(0);
  const failures = useRef(0);

  const clearRetry = useCallback(() => {
    if (retryTimer.current) {
      window.clearTimeout(retryTimer.current);
      retryTimer.current = null;
    }
  }, []);

  // Used by the retry timer, which cannot close over `load` before it is defined.
  const loadRef = useRef<(force: boolean) => void>(() => {});

  const load = useCallback((force: boolean): Promise<Health | null> => {
    // In-flight dedupe: focus + visibilitychange + the sidecar poll can all fire at once.
    if (inflight.current) return inflight.current;
    clearRetry();

    const ctrl = new AbortController();
    controller.current = ctrl;
    const p = health(force ? 1 : 0, ctrl.signal)
      .then((h) => {
        if (!alive.current) return null;
        if (h) {
          failures.current = 0;
          setData(h);
        } else if (document.visibilityState === 'visible') {
          failures.current = Math.min(failures.current + 1, 5);
          const delay = Math.min(RETRY_MAX_MS, RETRY_BASE_MS * 2 ** (failures.current - 1));
          retryTimer.current = window.setTimeout(() => {
            retryTimer.current = null;
            loadRef.current(false);
          }, delay);
        }
        return h;
      })
      .finally(() => {
        if (controller.current === ctrl) controller.current = null;
        if (inflight.current === p) inflight.current = null;
      });
    inflight.current = p;
    return p;
  }, [clearRetry]);

  loadRef.current = (force) => { void load(force); };

  const refresh = useCallback(() => { void load(true); }, [load]);

  useEffect(() => {
    alive.current = true;
    void load(false);

    const onVisibility = () => {
      if (document.visibilityState === 'visible') {
        void load(true);
      } else {
        // Hidden tab: stop retrying/polling. The next visibilitychange catches us up.
        clearRetry();
      }
    };
    window.addEventListener('focus', onVisibility);
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      alive.current = false;
      clearRetry();
      controller.current?.abort();
      controller.current = null;
      inflight.current = null;
      window.removeEventListener('focus', onVisibility);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [load, clearRetry]);

  const srv = data?.scanners?.joern?.server;
  const starting = !!(srv && srv.running && !srv.ready);
  useEffect(() => {
    if (!starting) { polls.current = 0; return; }
    if (polls.current >= SIDECAR_POLL_MAX) return;
    if (document.visibilityState !== 'visible') return;
    const t = window.setTimeout(() => {
      polls.current += 1;
      void load(true);
    }, SIDECAR_POLL_MS);
    return () => window.clearTimeout(t);
  }, [starting, data, load]);

  return (
    <HealthContext.Provider value={data}>
      <RefreshContext.Provider value={refresh}>{children}</RefreshContext.Provider>
    </HealthContext.Provider>
  );
}

export function useHealth(): Health | null {
  return useContext(HealthContext);
}

/** Re-fetch /api/health on demand (e.g. after a scan, so sidecar/DB state is current). */
export function useHealthRefresh(): () => void {
  return useContext(RefreshContext);
}
