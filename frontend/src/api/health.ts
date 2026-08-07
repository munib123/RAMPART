import { API } from '@/api/client';
import type { Health } from '@/types';

/** Fetch /api/health with retry/backoff while the backend cold-starts (chroma/onnx load). */
export async function health(attempts = 6): Promise<Health | null> {
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(API + '/api/health');
      return (await res.json()) as Health;
    } catch {
      if (i < attempts - 1) {
        await new Promise((r) => setTimeout(r, 2500 * (i + 1)));
        continue;
      }
      return null;
    }
  }
  return null;
}

export async function fetchAuthMe(headers: Record<string, string>) {
  const r = await fetch(API + '/api/auth/me', { headers });
  return r;
}