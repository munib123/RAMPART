import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import * as authApi from '@/api/auth';
import { ApiError, getToken, getUser, setSession } from '@/api/client';
import { tokenExpiryMs } from '@/utils/jwt';
import { clearReport } from '@/utils/reportStore';
import type { User } from '@/types';

interface AuthCtx {
  user: User | null;
  token: string;
  signIn: (email: string, password: string) => Promise<User>;
  signUp: (name: string, email: string, password: string) => Promise<User>;
  signOut: () => void;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthCtx | null>(null);

// Refresh a token this long before it expires, so a scan started near the end of a session is
// still saved. A failed refresh (backend down) retries; a 401 clears the session.
const REFRESH_LEAD_MS = 5 * 60 * 1000;
const REFRESH_RETRY_MS = 60 * 1000;
const MAX_TIMER_MS = 2_147_000_000;

function redirectToAuth() {
  if (!window.location.hash.startsWith('#/auth')) {
    window.location.hash = '#/auth?mode=login';
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => getUser());
  const token = getToken();
  const refreshing = useRef(false);

  const expire = useCallback(() => {
    setSession(null, null);
    setUser(null);
    clearReport();
    redirectToAuth();
  }, []);

  const commit = useCallback((nextToken: string, nextUser: User) => {
    setSession(nextToken, nextUser);
    setUser(nextUser);
  }, []);

  const signIn = useCallback(async (email: string, password: string) => {
    const r = await authApi.login(email, password);
    commit(r.token, r.user);
    return r.user;
  }, [commit]);

  const signUp = useCallback(async (name: string, email: string, password: string) => {
    const r = await authApi.signup(name, email, password);
    commit(r.token, r.user);
    return r.user;
  }, [commit]);

  const signOut = useCallback(() => {
    setSession(null, null);
    setUser(null);
    clearReport();
  }, []);

  const refreshUser = useCallback(async () => {
    const t = getToken();
    if (!t) return;
    try {
      const r = await authApi.me();
      if (r.user) { setSession(t, r.user); setUser(r.user); }
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) expire();
      /* backend down: keep the cached session */
    }
  }, [expire]);

  const refreshToken = useCallback(async (): Promise<boolean> => {
    if (refreshing.current) return true;
    if (!getToken()) return false;
    refreshing.current = true;
    try {
      const r = await authApi.refresh();
      commit(r.token, r.user);
      return true;
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        expire();
        return false;
      }
      return false;                 // backend down: keep the session and try again later
    } finally {
      refreshing.current = false;
    }
  }, [commit, expire]);

  // Keep the session alive: decode exp (unverified) and refresh shortly before it lapses.
  useEffect(() => {
    if (!token) return;
    const exp = tokenExpiryMs(token);
    if (exp === null) return;

    let cancelled = false;
    let timer = 0;
    const schedule = (delayMs: number) => {
      timer = window.setTimeout(async () => {
        if (cancelled) return;
        const ok = await refreshToken();
        if (!ok && !cancelled && getToken()) schedule(REFRESH_RETRY_MS);
      }, Math.max(0, Math.min(MAX_TIMER_MS, delayMs)));
    };

    const msLeft = exp - Date.now();
    schedule(msLeft <= 0 ? 0 : msLeft - REFRESH_LEAD_MS);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [token, refreshToken]);

  const value = useMemo(
    () => ({ user, token, signIn, signUp, signOut, refreshUser }),
    [user, token, signIn, signUp, signOut, refreshUser],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthCtx {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
