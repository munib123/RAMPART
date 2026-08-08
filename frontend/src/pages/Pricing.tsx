import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';
import { loadPlans, upgrade } from '@/api/profile';
import { announce } from '@/api/client';
import { Icon } from '@/components/Icons';
import type { PlanRow } from '@/types';

const FEATURES: Record<string, string[]> = {
  free: [
    'Semgrep + Bandit scanning',
    'RAG-grounded real-world exemplars',
    'Batch LLM verdicts',
    'Fixes for up to 5 scans',
  ],
  pro: [
    'Everything in Free',
    '30 scans & 20 fixes per month',
    'Advanced models for fixes & verification',
    'Priority support',
  ],
  premium: [
    'Everything in Pro',
    '500 scans & 200 fixes per month',
    'Advanced models for fixes & verification',
    'Priority reasoning + dedicated support',
  ],
};

const FEATURE_ROWS: { label: string; values: string[] }[] = [
  { label: 'Scans', values: ['10', '30', '500'] },
  { label: 'Fixes (one per scan)', values: ['5', '20', '200'] },
  { label: 'Verified verdicts', values: ['Yes', 'Yes', 'Yes'] },
  { label: 'Advanced models', values: ['—', 'Yes', 'Yes'] },
  { label: 'Support', values: ['Community', 'Priority', 'Dedicated'] },
];

const POPULAR = 'pro';

function formatPrice(p: PlanRow): { main: string; per: string } {
  if (typeof p.price === 'number' || !isNaN(Number(p.price))) {
    const n = Number(p.price);
    return { main: n === 0 ? '$0' : `$${n}`, per: n === 0 ? 'forever' : '/ month' };
  }
  const m = String(p.price).match(/\$?(\d+)\/mo/);
  if (m) return { main: `$${m[1]}`, per: '/ month' };
  return { main: String(p.price), per: '' };
}

export default function Pricing() {
  const { user, token } = useAuth();
  const navigate = useNavigate();
  const [plans, setPlans] = useState<PlanRow[]>([]);
  const [mine, setMine] = useState('free');
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState('');

  useEffect(() => {
    void (async () => {
      const p = await loadPlans().catch(() => [] as PlanRow[]);
      setPlans(p);
      setMine(user?.plan || 'free');
    })();
  }, [user]);

  const onUpgrade = async (key: string) => {
    if (!token) { navigate('/auth?mode=signup'); return; }
    if (key === mine) return;
    setBusy(key);
    try {
      const r = await upgrade(key);
      setMine(r.plan);
      setMsg('[Demo] ' + r.note + '');
      announce('Upgraded to ' + r.label + ' (demo, no charge)');
    } catch (e) {
      setMsg('Upgrade failed: ' + (e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const rows = plans.length ? plans : ([
    { key: 'free', label: 'Free', scans: 10, fixes: 5, price: 0 },
    { key: 'pro', label: 'Pro', scans: 30, fixes: 20, price: '$13/mo' },
    { key: 'premium', label: 'Premium', scans: 500, fixes: 200, price: '$30/mo' },
  ] as PlanRow[]);

  /* Persistent back: go one page back in history, else fall back home. */
  const goBack = () => {
    if (window.history.length > 1) navigate(-1);
    else navigate('/');
  };

  return (
    <section className="view" id="view-pricing">
      <div className="setup-head backbar">
        <button className="btn backbtn" onClick={goBack} aria-label="Go back" title="Go back">
          <Icon id="ic-arrow-left" />
        </button>
      </div>
      <div className="pricing-hero">
        <div className="eyebrow">PRICING</div>
        <h2>Simple plans that scale with your team</h2>
        <p>Static analysis, real-world grounding and LLM-verified verdicts — priced for every stage of your security practice.</p>
        {token && (
          <p className="pricing-mine">You're on the <strong>{mine}</strong> plan.</p>
        )}
        {msg && <div className="ok-note" role="status">{msg}</div>}
      </div>

      <div className="plan-grid">
        {rows.map((p) => {
          const current = token && p.key === mine;
          const canUp = token && p.key !== mine && (p.key === 'pro' || p.key === 'premium');
          const popular = p.key === POPULAR;
          const price = formatPrice(p);
          return (
            <article key={p.key} className={'plancard plan-' + p.key + (current ? ' is-mine' : '') + (popular ? ' is-popular' : '')}>
              {popular && <div className="plancard-flag">Most popular</div>}
              <div className="plancard-top">
                <h3 className="plancard-name">{p.label}</h3>
                <div className="plancard-price">
                  <span className="plancard-amount">{price.main}</span>
                  <span className="plancard-per">{price.per}</span>
                </div>
                <div className="plancard-limits">{p.scans} scans &amp; {p.fixes} fixes per month</div>
                {p.note && !current && <p className="plancard-note">{p.note}</p>}
              </div>
              <ul className="plancard-feats">
                {(FEATURES[p.key] || []).map((f, i) => (
                  <li key={i}><Icon id="ic-check" svgClass="plancard-check" />{f}</li>
                ))}
              </ul>
              <div className="plancard-cta">
                {!token ? (
                  <button className="btn btn-primary btn-block" onClick={() => navigate('/auth?mode=signup')}>Create free account</button>
                ) : current ? (
                  <div className="btn btn-block is-current" aria-disabled="true">Current plan</div>
                ) : canUp ? (
                  <button className="btn btn-primary btn-block" disabled={busy === p.key} onClick={() => onUpgrade(p.key)}>
                    {busy === p.key ? 'Upgrading…' : 'Upgrade to ' + p.label}
                  </button>
                ) : (
                  <div className="btn btn-block is-current" aria-disabled="true">Current plan</div>
                )}
              </div>
            </article>
          );
        })}
      </div>

      <div className="card compare">
        <h3 className="compare-title">Compare plans</h3>
        <table className="compare-table">
          <thead>
            <tr>
              <th></th>
              {rows.map((p) => <th key={p.key}>{p.label}</th>)}
            </tr>
          </thead>
          <tbody>
            {FEATURE_ROWS.map((row) => (
              <tr key={row.label}>
                <td className="compare-label">{row.label}</td>
                {row.values.map((v, i) => (
                  <td key={i} className={v === '—' ? 'is-na' : ''}>
                    {v === 'Yes' ? <Icon id="ic-check" svgClass="compare-check" /> : v}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        <div className="pricing-note"><span className="dot"></span> All tiers currently share the same working Gemini model; advanced model routing is staged for later.</div>
      </div>
    </section>
  );
}