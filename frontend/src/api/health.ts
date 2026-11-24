import { request } from '@/api/client';
import type { Health } from '@/types';

/** Fetch /api/health once. The HealthContext owns the cold-start retry/backoff policy. */
export async function health(refresh = 0, signal?: AbortSignal): Promise<Health | null> {
  try {
    return await request<Health>(
      `/api/health${refresh ? '?refresh=1' : ''}`,
      {},
      { timeoutMs: 20_000, retries: 0, signal },
    );
  } catch {
    return null;
  }
}

export async function fetchAuthMe(headers: Record<string, string>) {
  return request<unknown>('/api/auth/me', { headers }, { timeoutMs: 15_000, retries: 0 });
}
