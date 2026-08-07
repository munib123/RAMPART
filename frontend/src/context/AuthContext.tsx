import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';
import * as authApi from '@/api/auth';
import { getToken, getUser, setSession } from '@/api/client';
import type { User } from '@/types';

interface AuthCtx {
  user: User | null;
  token: string;
  signIn: (email: string, password: string) => Promise<User>;
  signUp: (email: string, password: string) => Promise<User>;
  signOut: () => void;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => getUser());
  const token = getToken();

  const commit = useCallback((token: string, user: User) => {
    setSession(token, user);
    setUser(user);
  }, []);

  const signIn = useCallback(async (email: string, password: string) => {
    const r = await authApi.login(email, password);
    commit(r.token, r.user);
    return r.user;
  }, [commit]);

  const signUp = useCallback(async (email: string, password: string) => {
    const r = await authApi.signup(email, password);
    commit(r.token, r.user);
    return r.user;
  }, [commit]);

  const signOut = useCallback(() => {
    setSession(null, null);
    setUser(null);
  }, []);

  const refreshUser = useCallback(async () => {
    const t = getToken();
    if (!t) return;
    try {
      const r = await fetch('http://127.0.0.1:8000/api/auth/me', {
        headers: { Authorization: 'Bearer ' + t },
      });
      if (r.ok) {
        const j = await r.json();
        if (j.user) { setSession(t, j.user); setUser(j.user); }
      } else if (r.status === 401) {
        setSession(null, null);
        setUser(null);
      }
    } catch { /* backend down: keep cached session */ }
  }, []);

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