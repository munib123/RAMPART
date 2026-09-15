import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';
import { useHealth } from '@/context/HealthContext';
import { loadHistory } from '@/api/history';
import { SEV_BAR_COLORS } from '@/utils/format';
import { scopeLabels } from '@/utils/scope';
import { Icon } from '@/components/Icons';
import type { HistoryRow } from '@/types';

export default function History() {
  const navigate = useNavigate();
  const { token } = useAuth();
  const health = useHealth();
  const [rows, setRows] = useState<HistoryRow[] | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    (async () => {
      if (!token) { setRows([]); return; }
      if (health && health.db_enabled === false) { setRows([]); return; }
      try {
        setRows(await loadHistory());
      } catch (e) {
        setError((e as Error).message || 'Could not load history.');
      }
    })();
  }, [token, health]);

  const totalOf = (s: HistoryRow) => {
    const c = s.counts || {};
    return (c.critical || 0) + (c.high || 0) + (c.medium || 0) + (c.low || 0);
  };
  const segsOf = (s: HistoryRow) => ['critical', 'high', 'medium', 'low'].filter((k) => s.counts && s.counts[k as keyof typeof s.counts]);

  const body = () => {
    if (!token) return <div className="hist-empty">You’re signed out. Sign in to see saved scans.</div>;
    if (health && health.db_enabled === false) return <div className="hist-empty">Database is not configured (set DATABASE_URL in .env), so scans aren’t being saved.</div>;
    if (error) return <div className="hist-empty">Could not load history. {error}</div>;
    if (rows === null) return <div className="hist-empty">Loading history…</div>;
    if (!rows.length) return <div className="hist-empty">No saved scans yet. Run a scan while signed in and it will appear here.</div>;
    return rows.map((s) => {
      const counts = s.counts || {};
      const total = totalOf(s);
      const segs = segsOf(s);
      const date = s.created_at ? new Date(s.created_at).toLocaleString() : '';
      const scopeLabelsFor = scopeLabels(s.scope);
      const j = (s.joern && 'used' in s.joern ? s.joern : null);
      const cpgTitle = j
        ? (j.used ? `Joern CPG phase ran (${j.mode || 'script'} mode) · ${j.candidates ?? 0} candidate${(j.candidates ?? 0) === 1 ? '' : 's'}` : `CPG phase skipped: ${j.reason || 'n/a'}`)
        : '';
      return (
        <div className="hist-card" key={s.id}>
          <div className="hist-row">
            <span className="pill mono">{s.scanner || ''}</span>
            {j && j.used && <span className="pill mono cpg sm" title={cpgTitle}>+ CPG {j.candidates ?? 0}</span>}
            <span className="hist-target">{s.target || '(unknown target)'}</span>
            <span className="hist-meta">{date}</span>
          </div>
          {scopeLabelsFor.length ? (
            <div className="hist-scope">
              {scopeLabelsFor.map((l) => <span key={l} className="scope-pill">{l}</span>)}
            </div>
          ) : null}
          {segs.length ? (
            <div className="hist-sevbar">
              {segs.map((k) => (
                <span key={k} className="hist-seg" style={{ background: SEV_BAR_COLORS[k], width: ((Number(counts[k as keyof typeof counts]) || 0) / total) * 100 + '%' }} title={`${counts[k as keyof typeof counts]} ${k}`}></span>
              ))}
            </div>
          ) : null}
        </div>
      );
    });
  };

  return (
    <section className="view" id="view-history">
      <div className="setup-head">
        <button className="btn icon-btn" onClick={() => navigate('/setup')} title="Back to setup" aria-label="Back"><Icon id="ic-arrow-left" /></button>
        <div>
          <h2>Scan history</h2>
          <p>Your saved scans, stored locally-scoped and anonymised (raw code never leaves your machine).</p>
        </div>
      </div>
      <div id="historyList">{body()}</div>
    </section>
  );
}