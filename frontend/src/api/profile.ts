import { authHeaders, request } from '@/api/client';
import type { PlanInfo, PlanRow } from '@/types';

export interface ProfileResponse {
  user: { id: string; name: string; email: string; created_at?: string; plan?: string };
  usage: PlanInfo;
}

export async function loadProfile(): Promise<ProfileResponse> {
  return request<ProfileResponse>('/api/profile', { headers: authHeaders() });
}

export async function updateName(name: string): Promise<ProfileResponse> {
  return request<ProfileResponse>('/api/profile', {
    method: 'PUT',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ name }),
  }, { timeoutMs: 20_000, retries: 0 });
}

export async function changePassword(old_password: string, new_password: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>('/api/auth/change-password', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ old_password, new_password }),
  }, { timeoutMs: 20_000, retries: 0 });
}

export async function billingInfo(): Promise<PlanInfo> {
  return request<PlanInfo>('/api/billing', { headers: authHeaders() });
}

export async function loadPlans(): Promise<PlanRow[]> {
  const j = await request<{ plans?: PlanRow[] }>('/api/billing/plans');
  return j.plans || [];
}

export interface UpgradeResult {
  ok: boolean;
  plan: string;
  label?: string;
  note?: string;
}

export async function upgrade(plan: string): Promise<UpgradeResult> {
  return request<UpgradeResult>('/api/billing/upgrade', {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ plan }),
  }, { timeoutMs: 20_000, retries: 0 });
}
