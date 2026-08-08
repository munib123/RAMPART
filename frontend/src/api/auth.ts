import { API } from '@/api/client';
import type { AuthResponse } from '@/types';

export async function signup(name: string, email: string, password: string): Promise<AuthResponse> {
  const res = await fetch(API + '/api/auth/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, password }),
  });
  const j = await res.json();
  if (!res.ok) throw new Error(j.detail || `Request failed (${res.status})`);
  return j as AuthResponse;
}

export async function login(email: string, password: string): Promise<AuthResponse> {
  const res = await fetch(API + '/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const j = await res.json();
  if (!res.ok) throw new Error(j.detail || `Request failed (${res.status})`);
  return j as AuthResponse;
}