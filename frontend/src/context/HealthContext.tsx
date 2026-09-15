import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { health } from '@/api/health';
import type { Health } from '@/types';

const HealthContext = createContext<Health | null>(null);
const RefreshContext = createContext<() => void>(() => {});

// The Joern sidecar comes up 15-40 s after the backend does; while /api/health says
// "running but not ready" we poll so the Setup page's CPG note flips to "ready" on its own.
const SIDECAR_POLL_MS = 5000;
const SIDECAR_POLL_MAX = 24;          // 2 min, then stop and wait for the next focus/refresh

export function HealthProvider({ children }: { children: ReactNode }) {
  const [data, setData] = useState<Health | null>(null);
  const alive = useRef(true);
  const polls = useRef(0);

  const refresh = useCallback(() => {
    void health(1).then((h) => { if (alive.current && h) setData(h); });
  }, []);

  useEffect(() => {
    alive.current = true;
    void health().then((h) => { if (alive.current) setData(h); });
    const onFocus = () => { if (document.visibilityState === 'visible') refresh(); };
    window.addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onFocus);
    return () => {
      alive.current = false;
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onFocus);
    };
  }, [refresh]);

  const srv = data?.scanners?.joern?.server;
  const starting = !!(srv && srv.running && !srv.ready);
  useEffect(() => {
    if (!starting) { polls.current = 0; return; }
    if (polls.current >= SIDECAR_POLL_MAX) return;
    const t = window.setTimeout(() => { polls.current += 1; refresh(); }, SIDECAR_POLL_MS);
    return () => window.clearTimeout(t);
  }, [starting, data, refresh]);

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
