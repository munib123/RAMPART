import { API, authHeaders } from '@/api/client';
import type { PlanInfo, PlanRow } from '@/types';

export interface ProfileResponse {
  user: { id: string; name: string; email: string; created_at?: string; plan?: string };
  usage: PlanInfo;
}

export async function loadProfile(): Promise<ProfileResponse> {
  const r = await fetch(API + '/api/profile', { headers: authHeaders() });
  if (!r.ok) throw new Error(`Request failed (${r.status})`);
  return (await r.json()) as ProfileResponse;
}

export async function updateName(name: string): Promise<ProfileResponse> {
  const r = await fetch(API + '/api/profile', {
    method: 'PUT',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ name }),
  });
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error((j && j.detail) || `Request failed (${r.status})`);
  }
  return (await r.json()) as ProfileResponse;
}

export async function changePassword(old_password: string, new_password: string): Promise<{ ok: boolean }> {
  const r = await fetch(API + '/api/auth/change-password', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ old_password, new_password }),
  });
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error((j && j.detail) || `Request failed (${r.status})`);
  }
  return (await r.json()) as { ok: boolean };
}

export async function billingInfo(): Promise<PlanInfo> {
  const r = await fetch(API + '/api/billing', { headers: authHeaders() });
  if (!r.ok) throw new Error(`Request failed (${r.status})`);
  return (await r.json()) as PlanInfo;
}

export async function loadPlans(): Promise<PlanRow[]> {
  const r = await fetch(API + '/api/billing/plans');
  if (!r.ok) throw new Error(`Request failed (${r.status})`);
  const j = (await r.json()) as { plans?: PlanRow[] };
  return j.plans || [];
}

export interface UpgradeResult {
  ok: boolean;
  plan: string;
  label?: string;
  note?: string;
}

export async function upgrade(plan: string): Promise<UpgradeResult> {
  const r = await fetch(API + '/api/billing/upgrade', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ plan }),
  });
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error((j && j.detail) || `Request failed (${r.status})`);
  }
  return (await r.json()) as UpgradeResult;
}