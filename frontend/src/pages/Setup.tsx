import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';
import { useHealth } from '@/context/HealthContext';
import { browse } from '@/api/scan';
import { billingInfo } from '@/api/profile';
import { PLATFORM_LABELS, STACK_LABELS, PRIORITY_LABELS, scopeLabels } from '@/utils/scope';
import { Icon } from '@/components/Icons';
import type { Scope } from '@/types';

const PLATFORMS = ['generic', 'cms', 'lms', 'medical', 'ecommerce', 'api'];
const STACKS = ['python', 'javascript', 'php', 'java', 'go', 'other'];
const PRIORITIES = ['access-control', 'injection', 'secrets', 'dos', 'supply-chain'];

function SpikeIcon({ d, viewBox }: { d: string; viewBox?: string }) {
  return (
    <span className="picon">
      <svg viewBox={viewBox || '0 0 24 24'} fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d={d} />
      </svg>
    </span>
  );
}

const PLATFORM_ICON: Record<string, { d: string; viewBox?: string }> = {
  generic: { d: 'M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20M2 12h20' },
  cms: { d: 'M4 22h16a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v16a2 2 0 0 1-2 2Zm0 0a2 2 0 0 1-2-2v-9c0-1.1.9-2 2-2h2M18 14h-8M15 18h-5M10 6h8v4h-8V6Z' },
  lms: { d: 'M21.42 10.922a1 1 0 0 0-.019-1.838L12.83 5.18a2 2 0 0 0-1.66 0L2.6 9.08a1 1 0 0 0 0 1.832l8.57 3.908a2 2 0 0 0 1.66 0zM22 10v6M6 12.5V16a6 3 0 0 0 12 0v-3.5' },
  medical: { d: 'M19 14c1.49-1.46 3-3.21 3-5.5A5.5 5.5 0 0 0 16.5 3c-1.76 0-3 .5-4.5 2-1.5-1.5-2.74-2-4.5-2A5.5 5.5 0 0 0 2 8.5c0 2.3 1.5 4.05 3 5.5l7 7ZM3.22 12H9.5l.5-1 2 4.5 2-7 1.5 3.5h5.27' },
  ecommerce: { d: 'M8 21a1 1 0 1 0 0-2 1 1 0 0 0 0 2Zm11 0a1 1 0 1 0 0-2 1 1 0 0 0 0 2ZM2.05 2.05h2l2.66 12.42a2 2 0 0 0 2 1.58h9.78a2 2 0 0 0 1.95-1.57l1.65-7.43H5.12', viewBox: '0 0 24 24' },
  api: { d: 'M2 2h20v8H2zM2 14h20v8H2zM6 6h.01M6 18h.01', viewBox: '0 0 24 24' },
};

export default function Setup() {
  const navigate = useNavigate();
  const { token, user } = useAuth();
  const health = useHealth();

  const [platform, setPlatform] = useState<string | null>(null);
  const [stack, setStack] = useState<string[]>([]);
  const [priorities, setPriorities] = useState<string[]>([]);
  const [path, setPath] = useState(health?.default_target || '');
  const [scanner, setScanner] = useState('auto');
  const [browsing, setBrowsing] = useState(false);
  const [running, setRunning] = useState(false);
  const [quota, setQuota] = useState<{ used: number; limit: number } | null>(null);

  useEffect(() => {
    if (!token || !health?.db_enabled) return;
    let alive = true;
    void billingInfo().then((b) => { if (alive) setQuota(b.scans ?? null); }).catch(() => {});
    return () => { alive = false; };
  }, [token, health?.db_enabled]);

  const ready = platform != null && stack.length > 0 && priorities.length > 0;

  const scope: Scope = useMemo(() => {
    const s: Scope = { stack, priorities };
    if (platform) s.platform = platform;
    return s;
  }, [platform, stack, priorities]);
  const labels = scopeLabels(scope);
  const missing = ready ? '' : [
    platform == null ? 'platform' : '',
    stack.length === 0 ? 'stack' : '',
    priorities.length === 0 ? 'priorities' : '',
  ].filter(Boolean).join(', ');

  const toggleChip = (arr: string[], set: (v: string[]) => void, v: string) =>
    set(arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v]);

  const onBrowse = async () => {
    setBrowsing(true);
    const r = await browse();
    if (r.path) setPath(r.path);
    setBrowsing(false);
  };

  const run = () => {
    if (!ready) return;
    if (!token) { navigate('/auth?mode=signup'); return; }
    setRunning(true);
    navigate('/scan', { state: { path, scanner, scope } });
  };

  const sg = (health?.scanners && health.scanners.semgrep) as { available?: boolean } | undefined;
  const sgAvail = !!(sg && sg.available);
  let note = sgAvail
    ? 'Semgrep is active · multi-language'
    : 'Semgrep unavailable, so Bandit (Python) is used for now.';
  if (!health?.llm_enabled) note += ' Set GEMINI_API_KEY in .env for verified verdicts.';
  const noteCls = 'avail-note' + (sgAvail && health?.llm_enabled ? '' : ' warn');

  const quotaPill = quota ? (quota.used >= quota.limit ? 'out' : '') : 'hide';
  const quotaText = quota
    ? quota.used >= quota.limit
      ? `${quota.used}/${quota.limit} scans · limit reached`
      : `${quota.used}/${quota.limit} scans`
    : '';

  if (!token || !user) {
    return null; // guarded by route; brief blank while auth resolves
  }

  return (
    <section className="view" id="view-setup">
      <div className="setup-head">
        <button className="btn icon-btn" id="backBtn" title="Back to home" aria-label="Back to home" onClick={() => navigate('/')}>
          <Icon id="ic-arrow-left" />
        </button>
        <div>
          <h2>Set up your scan</h2>
          <p>A little context sharpens the results. RAMPART weighs the weaknesses that matter for your kind of software.</p>
        </div>
      </div>

      <div className="setup-grid">
        <div className="setup-left">
          <div className="scard">
            <div className="scard-head">
              <span className="num-chip">1</span>
              <div className="scard-label">What are you scanning?</div>
              <span className="opt req">required</span>
            </div>
            <div className="platform-grid" id="platform" role="group" aria-label="What are you scanning?">
              {PLATFORMS.map((p) => (
                <button key={p} type="button" className={'plat-btn ' + (platform === p ? 'is-on' : '')} data-val={p} aria-pressed={platform === p} onClick={() => setPlatform(p)}>
                  <SpikeIcon d={PLATFORM_ICON[p].d} viewBox={PLATFORM_ICON[p].viewBox} />
                  <span className="plabel">{PLATFORM_LABELS[p]}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="scard">
            <div className="scard-head">
              <span className="num-chip">2</span>
              <div className="scard-label">Tech stack</div>
              <span className="opt req">required</span>
            </div>
            <div className="chips" id="stack">
              {STACKS.map((s) => (
                <button key={s} type="button" className={'chip ' + (stack.includes(s) ? 'is-on' : '')} data-val={s} aria-pressed={stack.includes(s)} onClick={() => toggleChip(stack, setStack, s)}>
                  {STACK_LABELS[s]}
                </button>
              ))}
            </div>
          </div>

          <div className="scard">
            <div className="scard-head">
              <span className="num-chip">3</span>
              <div className="scard-label">Priority concerns</div>
              <span className="opt req">required</span>
            </div>
            <div className="chips" id="priorities">
              {PRIORITIES.map((p) => (
                <button key={p} type="button" className={'chip ' + (priorities.includes(p) ? 'is-on' : '')} data-val={p} aria-pressed={priorities.includes(p)} onClick={() => toggleChip(priorities, setPriorities, p)}>
                  {PRIORITY_LABELS[p]}
                </button>
              ))}
            </div>
            <div className="scard-note">All three are required — RAMPART stores them to categorize your scans.</div>
          </div>
        </div>

        <div className="runcard">
          <label className="runcard-label" htmlFor="path">Code to scan</label>
          <div className="path-row">
            <input type="text" id="path" placeholder="C:\path\to\your\code" spellCheck={false} value={path} onChange={(e) => setPath(e.target.value)} />
            <button type="button" className="btn" id="browseBtn" onClick={onBrowse} disabled={browsing}>{browsing ? 'Opening…' : 'Browse…'}</button>
          </div>
          <div className="scanner-row">
            <label htmlFor="scanner">Scanner</label>
            <select id="scanner" value={scanner} onChange={(e) => setScanner(e.target.value)}>
              <option value="auto">Auto</option>
              <option value="semgrep">Semgrep</option>
              <option value="bandit">Bandit</option>
            </select>
          </div>
          <div className={noteCls} id="scanNote"><span className="dot"></span><span>{note}</span></div>
          <hr />
          <div>
            <div className="scope-label">Scope summary</div>
            <div className="scope-pills" id="scopeSummary">
              {labels.length
                ? labels.map((l) => <span key={l} className="scope-pill">{l}</span>)
                : <span className="scope-empty">Select a platform, stack and priorities above</span>}
            </div>
          </div>
          {!ready && (
            <div className="setup-required-hint" role="status"><span className="dot warn"></span>Required to run the scan: {missing}.</div>
          )}
          <button className="btn btn-primary btn-block" id="runBtn" onClick={run} disabled={running || !ready}>{running ? 'Starting…' : (ready ? 'Run scan' : 'Select scan options')}</button>
          <div className="run-caption">One batched LLM call per scan · nothing is auto-applied</div>
          {quota && (
            <div className={'quota-pill ' + quotaPill} data-noprint>
              <span className="dot"></span>{quotaText}
              {quota.used >= quota.limit && ' · '}
              {quota.used >= quota.limit && <a href="#/pricing">Upgrade</a>}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}