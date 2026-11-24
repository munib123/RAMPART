// API base + fetch helper. Absolute URL so it works from Vite (:5173), the Tauri
// webview, and a browser (CORS-enabled on the backend at 127.0.0.1:8000).
//
// `request()` adds a timeout, retries idempotent GETs on transient gateway errors, and throws a
// structured ApiError. Callers that need to inspect a non-2xx body (e.g. the 402 plan-limit
// passthrough, or a 401 during CPG verify) can opt in with `allowStatus`.
import type { Scope } from '@/types';

export const API = 'http://127.0.0.1:8000';

export const TOKEN_KEY = 'rampart.token';
export const USER_KEY = 'rampart.user';

export const DEFAULT_TIMEOUT_MS = 30_000;
const RETRY_DELAYS_MS = [250, 750, 1500];
const RETRYABLE_STATUS = new Set([502, 503, 504]);

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

export class ApiError extends Error {
  status: number;
  code?: string;
  requestId?: string;
  body?: unknown;

  constructor(message: string, status = 0, code?: string, body?: unknown, requestId?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.body = body;
    this.requestId = requestId;
  }
}

export interface RequestOptions {
  /** Abort the request after this many ms. Default 30 s; scans/fixes pass longer values. */
  timeoutMs?: number;
  /** Override the retry count. GETs default to 2; other methods default to 0. */
  retries?: number;
  /** Caller cancellation (e.g. the Scan page's Cancel button). */
  signal?: AbortSignal;
  /** Non-2xx statuses whose parsed JSON body should be returned instead of throwing. */
  allowStatus?: number[];
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseBody(text: string): unknown {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function field(body: unknown, key: string): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const value = (body as Record<string, unknown>)[key];
  return typeof value === 'string' && value ? value : undefined;
}

function errorMessage(body: unknown, status: number): string {
  const explicit = field(body, 'error') || field(body, 'detail');
  if (explicit) return explicit;
  if (typeof body === 'string' && body.trim()) return body.trim().slice(0, 200);
  return `Request failed (${status})`;
}

export async function request<T>(
  path: string,
  init: RequestInit = {},
  opts: RequestOptions = {},
): Promise<T> {
  const url = /^https?:\/\//i.test(path) ? path : API + path;
  const method = (init.method || 'GET').toUpperCase();
  const idempotent = method === 'GET' || method === 'HEAD';
  const maxRetries = Math.max(0, opts.retries ?? (idempotent ? 2 : 0));
  const allowStatus = new Set(opts.allowStatus || []);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const caller = opts.signal ?? init.signal ?? null;

  let lastError: unknown = null;

  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    if (attempt > 0) {
      const delay = RETRY_DELAYS_MS[Math.min(attempt - 1, RETRY_DELAYS_MS.length - 1)];
      await sleep(delay);
    }

    const ctrl = new AbortController();
    let timedOut = false;
    let callerAborted = false;
    const onCallerAbort = () => {
      callerAborted = true;
      ctrl.abort();
    };
    if (caller) {
      if (caller.aborted) {
        callerAborted = true;
        ctrl.abort();
      } else {
        caller.addEventListener('abort', onCallerAbort, { once: true });
      }
    }
    const timer = setTimeout(() => {
      timedOut = true;
      ctrl.abort();
    }, timeoutMs);

    try {
      const res = await fetch(url, { ...init, signal: ctrl.signal });
      const body = parseBody(await res.text());

      if (allowStatus.has(res.status)) return body as T;
      if (!res.ok) {
        const err = new ApiError(
          errorMessage(body, res.status), res.status, field(body, 'code'), body,
          field(body, 'request_id'),
        );
        if (idempotent && RETRYABLE_STATUS.has(res.status) && attempt < maxRetries) {
          lastError = err;
          continue;
        }
        throw err;
      }
      return body as T;
    } catch (e) {
      if (e instanceof ApiError) throw e;
      // Caller cancellation is not an error from our side: preserve AbortError so the Scan
      // page's cancel path can ignore it.
      if (callerAborted) throw e;
      if (timedOut) {
        lastError = new ApiError(
          `The backend did not respond within ${Math.round(timeoutMs / 1000)} s. Is it running?`,
          0, 'timeout',
        );
      } else {
        lastError = new ApiError(
          'Cannot reach the RAMPART backend. Is it running?', 0, 'network',
        );
      }
      if (attempt < maxRetries) continue;
      throw lastError;
    } finally {
      clearTimeout(timer);
      if (caller) caller.removeEventListener('abort', onCallerAbort);
    }
  }

  throw lastError ?? new ApiError('Request failed', 0, 'unknown');
}
