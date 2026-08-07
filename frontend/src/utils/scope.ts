// Scope label maps + helpers (ported from the legacy app.js).
import type { Scope } from '@/types';

export const PLATFORM_LABELS: Record<string, string> = {
  generic: 'Web app', cms: 'CMS', lms: 'LMS', medical: 'Medical',
  ecommerce: 'E-commerce', api: 'Internal API',
};
export const STACK_LABELS: Record<string, string> = {
  python: 'Python', javascript: 'JavaScript', php: 'PHP', java: 'Java', go: 'Go', other: 'Other',
};
export const PRIORITY_LABELS: Record<string, string> = {
  'access-control': 'Access control & auth', injection: 'Injection',
  secrets: 'Secrets & crypto', dos: 'Denial of service', 'supply-chain': 'Supply chain',
};

export function scopeLabels(scope?: Scope | null): string[] {
  if (!scope) return [];
  const out: string[] = [];
  if (scope.platform && scope.platform !== 'generic') out.push(PLATFORM_LABELS[scope.platform] || scope.platform);
  (scope.stack || []).forEach((s) => out.push(STACK_LABELS[s] || s));
  (scope.priorities || []).forEach((p) => out.push(PRIORITY_LABELS[p] || p));
  return out;
}