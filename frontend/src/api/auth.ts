import { authHeaders, request } from '@/api/client';
import type { AuthResponse, User } from '@/types';

const AUTH_TIMEOUT_MS = 15_000;

export async function signup(name: string, email: string, password: string): Promise<AuthResponse> {
  return request<AuthResponse>('/api/auth/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, password }),
  }, { timeoutMs: AUTH_TIMEOUT_MS, retries: 0 });
}

export async function login(email: string, password: string): Promise<AuthResponse> {
  return request<AuthResponse>('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  }, { timeoutMs: AUTH_TIMEOUT_MS, retries: 0 });
}

/** Re-read the user row for the current token; 401 means the session is gone. */
export async function me(): Promise<{ user: User }> {
  return request<{ user: User }>('/api/auth/me', { headers: authHeaders() },
    { timeoutMs: AUTH_TIMEOUT_MS, retries: 0 });
}

/** Exchange a still-valid token for a fresh one (no schema change). */
export async function refresh(): Promise<AuthResponse> {
  return request<AuthResponse>('/api/auth/refresh', {
    method: 'POST',
    headers: authHeaders(),
  }, { timeoutMs: AUTH_TIMEOUT_MS, retries: 0 });
}
