import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { health } from '@/api/health';
import type { Health } from '@/types';

const HealthContext = createContext<Health | null>(null);

export function HealthProvider({ children }: { children: ReactNode }) {
  const [data, setData] = useState<Health | null>(null);

  useEffect(() => {
    let alive = true;
    health().then((h) => { if (alive) setData(h); });
    return () => { alive = false; };
  }, []);

  return <HealthContext.Provider value={data}>{children}</HealthContext.Provider>;
}

export function useHealth(): Health | null {
  return useContext(HealthContext);
}