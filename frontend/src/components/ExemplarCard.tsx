import { esc } from '@/utils/format';
import type { Exemplar } from '@/types';

export function ExemplarCard({ e }: { e: Exemplar }) {
  const src = String(e.source || '').toLowerCase();
  const sim = typeof e.sim === 'number' ? e.sim.toFixed(2) : e.sim;
  const url = safeUrlLocal(e.url || '');
  return (
    <div className="ex">
      <div className="exhead">
        <span className={'pill src-' + esc(src)}>{e.source || 'kb'}</span>
        <span className="pill mono ex-cwe">{e.cwe_id || ''}</span>
        <span className="ex-sim">sim {String(sim)}</span>
      </div>
      <div className="extitle">{e.title || '(untitled)'}</div>
      <div className="extext">{(e.text || '').slice(0, 240)}</div>
      {url && <a className="exlink" href={url} target="_blank" rel="noopener noreferrer">source</a>}
    </div>
  );
}

function urlIsSafe(u: string): string {
  try {
    const p = new URL(u, window.location.href);
    return p.protocol === 'http:' || p.protocol === 'https:' ? p.href : '';
  } catch {
    return '';
  }
}

function safeUrlLocal(u: string): string {
  return u ? urlIsSafe(u) : '';
}