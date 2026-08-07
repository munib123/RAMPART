// Shared format helpers (ported verbatim from the legacy app.js).

export const esc = (s: unknown): string =>
  s == null ? '' : String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' } as Record<string, string>)[c]);

export const cap = (s: string): string => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

export const fmtN = (n: unknown): string =>
  typeof n === 'number' ? n.toLocaleString('en-US') : (n ?? '?') as string;

// verdict names come from the LLM - strip to letters so they are safe in a class attribute
export function vClassOf(name: string): string {
  return 'v-' + cap(String(name || 'Unverified')).replace(/[^A-Za-z]/g, '');
}

// exemplar URLs come from KB data - only allow http(s)
export function safeUrl(u: string): string {
  try {
    const p = new URL(u, window.location.href);
    return p.protocol === 'http:' || p.protocol === 'https:' ? p.href : '';
  } catch {
    return '';
  }
}

export function langOf(path?: string): string {
  const base = (path || '').split(/[\\/]/).pop() || '';
  const ext = base.includes('.') ? base.split('.').pop()?.toLowerCase() || '' : '';
  return ({ py: 'python', js: 'javascript', ts: 'typescript', php: 'php', java: 'java', go: 'go', rb: 'ruby' } as Record<string, string>)[ext] || ext || 'code';
}

export const SEV_BAR_COLORS: Record<string, string> = {
  critical: 'var(--red-600)',
  high: 'var(--red-500)',
  medium: 'var(--amber-500)',
  low: 'var(--blue-400)',
};
