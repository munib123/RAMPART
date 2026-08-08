import { useEffect, useRef, useState } from 'react';
import { generateFix } from '@/api/history';
import { announce } from '@/api/client';
import { esc, langOf } from '@/utils/format';
import { diffLines, diffReact } from '@/utils/diff';
import { Icon } from '@/components/Icons';
import PlanLimitCard from '@/components/PlanLimitCard';
import type { DiffLine, Exemplar, Finding, FixState, PlanLimitPayload } from '@/types';

interface Props {
  finding: Finding;
  scanId?: string;
  onRegenerate?: () => void;
}

async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); return true; }
  } catch { /* fall through */ }
  try {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.left = '-9999px';
    document.body.appendChild(ta); ta.focus(); ta.select();
    const ok = document.execCommand('copy'); document.body.removeChild(ta); return ok;
  } catch { return false; }
}

export default function FixPanel({ finding, scanId }: Props) {
  const [fx, setFx] = useState<FixState>({ loading: true });
  const [view, setView] = useState<'diff' | 'full'>('diff');
  const [copied, setCopied] = useState(false);
  const btnRef = useRef<HTMLButtonElement | null>(null);
  const requestId = useRef(0);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void run();
  }, []);

  const run = async () => {
    const id = ++requestId.current;
    setFx({ loading: true });
    try {
      const r = await generateFix({
        code: (finding.slice && finding.slice.code) || '',
        cwe_id: finding.cwe_id,
        title: (finding.verdict && finding.verdict.vuln_class) || finding.title,
        message: finding.message,
        exemplars: finding.exemplars as Exemplar[],
        scan_id: scanId,
      });
      if (requestId.current !== id) return;
      if (r.code === 'plan_limit') {
        const payload: PlanLimitPayload = { code: r.code, kind: (r.kind as 'scan' | 'fix') || 'fix', plan: r.plan, used: r.used, limit: r.limit };
        setFx({ limit: payload });
        announce('Fix limit reached for your plan');
        return;
      }
      if (r.code === 'auth_required') {
        setFx({ error: true });
        announce('Sign in to suggest a fix');
        return;
      }
      setFx({ fixed_code: r.fixed_code || '', summary: r.summary || '', error: !r.available || !r.fixed_code });
      setView('diff');
      announce(r.available && r.fixed_code ? 'Suggested fix ready' : 'No automated fix available');
    } catch {
      if (requestId.current !== id) return;
      setFx({ error: true });
      announce('No automated fix available');
    }
  };

  // plan limit upsell
  if (fx.limit) {
    return <div className="fixwrap"><PlanLimitCard limit={fx.limit} label="Upgrade to keep fixing" /></div>;
  }

  const onCopy = async () => {
    const ok = await copyText(fx.fixed_code || '');
    announce(ok ? 'Corrected code copied to clipboard' : 'Copy failed');
    setCopied(ok);
    if (btnRef.current) btnRef.current.textContent = ok ? 'Copied ✓' : 'Copy failed';
    setTimeout(() => { setCopied(false); if (btnRef.current) btnRef.current.textContent = 'Copy fix'; }, 2000);
  };

  // loading panel
  if (fx.loading) {
    return <div className="fixpanel fixloading"><span className="spinner"></span> Generating fix…</div>;
  }

  // error / no fix
  if (fx.error || !fx.fixed_code) {
    const guide = finding.verdict && finding.verdict.fix_suggestion ? ` <span class="muted">Guidance: ${esc(finding.verdict.fix_suggestion)}</span>` : '';
    return (
      <div className="fixpanel nofix">
        No automated fix available for this finding.
        <span dangerouslySetInnerHTML={{ __html: guide }} />
        <div data-noprint><button className="btn btn-xs" onClick={run}>Try again</button></div>
      </div>
    );
  }

  const confN = (finding.verdict && finding.verdict.confidence) || 0;
  const tier = confN >= 80 ? 'High' : confN >= 50 ? 'Medium' : 'Low';
  const original = (finding.slice && finding.slice.code) || '';
  const diff = diffLines(original, fx.fixed_code);
  const changed = diff.filter((d: DiffLine) => d.t !== 'ctx').length;
  const nearTotal = !original || (diff.length && changed / diff.length > 0.7);
  const useView: 'diff' | 'full' = nearTotal ? 'full' : view;
  const legend = useView === 'diff' ? '<div class="difflegend"><span class="lg-add">+ added</span><span class="lg-del">− removed</span></div>' : '';
  const nearNote = nearTotal ? '<div class="nearnote">Shown as a suggested replacement (the change is a near-total rewrite).</div>' : '';

  return (
    <div className="fixpanel ready">
      <div className="fixhead">
        <span className="pill ai"><Icon id="ic-sparkles" />AI-generated</span>
        <span className={'pill tier-' + tier}>{tier} confidence</span>
        <span className="fixlang">{langOf(finding.path)}</span>
        <span className="fixhead-actions" data-noprint>
          {!nearTotal && (
            <span className="seg-toggle" role="group" aria-label="Fix view">
              <button className={'segb ' + (useView === 'diff' ? 'is-on' : '')} aria-pressed={useView === 'diff'} onClick={() => setView('diff')}>Diff</button>
              <button className={'segb ' + (useView === 'full' ? 'is-on' : '')} aria-pressed={useView === 'full'} onClick={() => setView('full')}>Full code</button>
            </span>
          )}
          <button className="btn btn-xs" onClick={run}>Regenerate</button>
          <button className={'btn btn-xs copybtn' + (copied ? ' copied' : '')} ref={btnRef} aria-label="Copy corrected code" onClick={onCopy}>Copy fix</button>
        </span>
      </div>
      <div className="caveat">{tier === 'Low' ? 'Low confidence: verify manually. ' : ''}AI-suggested fix. Review and test before using.</div>
      {fx.summary && <div className="whatchanged"><b>What changed.</b> {fx.summary}</div>}
      <div className="codearea">
        <div dangerouslySetInnerHTML={{ __html: legend + nearNote }} />
        {useView === 'full' ? <pre className="fcode">{fx.fixed_code}</pre> : diffReact(diff)}
      </div>
    </div>
  );
}