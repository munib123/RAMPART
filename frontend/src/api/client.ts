// API base + fetch helper. Absolute URL so it works from Vite (:5173), the Tauri
// webview, and a browser (CORS-enabled on the backend at 127.0.0.1:8000).
import type { Scope } from '@/types';

export const API = 'http://127.0.0.1:8000';

export const TOKEN_KEY = 'rampart.token';
export const USER_KEY = 'rampart.user';

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) || '';
}

export function getUser() {
  try {
    return JSON.parse(localStorage.getItem(USER_KEY) || 'null') || null;
  } catch {
    return null;
  }
}

export function setSession(token: string | null, user: unknown) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
  if (user) localStorage.setItem(USER_KEY, JSON.stringify(user));
  else localStorage.removeItem(USER_KEY);
}

export function authHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const t = getToken();
  return t ? { Authorization: 'Bearer ' + t, ...extra } : extra;
}

export function announce(msg: string) {
  const l = document.getElementById('live');
  if (l) l.textContent = msg;
}

export interface ScanPayload {
  path: string;
  scanner: string;
  scope: Scope;
}