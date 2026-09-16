import type { VerifyResult } from '@/types';

/** The one-line verdict of a CPG re-verification (P8), shared by the finding card and the fix panel. */
export default function VerifyNote({ v }: { v: VerifyResult }) {
  const cls = !v.ok ? 'err' : v.converged ? 'ok' : 'warn';
  const text = !v.ok
    ? (v.error || 'Verification failed.')
    : v.converged
      ? `Verified${v.mode === 'preview' ? ' on a scratch copy' : ' on the file as it is now'}: the locator no longer fires. ${v.reason || ''}`
      : `Not verified: ${v.reason || 'the locator still fires.'}`;
  return (
    <div className={'verify-note ' + cls} data-testid="verify-note">
      <span className="pill mono cpg sm">{v.reverify_method === 'pattern' ? 'PATTERN' : 'CPG'}</span>
      <span>
        {text}
        {v.ok && v.reverify_method === 'pattern' ? ' (weaker text check — Joern is not available)' : ''}
        {v.ok && typeof v.elapsed_ms === 'number' ? ` · ${(v.elapsed_ms / 1000).toFixed(1)}s` : ''}
      </span>
      {v.code === 'auth_required' && (
        <button className="btn btn-xs" data-noprint onClick={() => { window.location.hash = '#/auth'; }}>Sign in</button>
      )}
    </div>
  );
}
