import { useState } from 'react';
import { cap, esc, vClassOf } from '@/utils/format';
import { Icon } from '@/components/Icons';
import Collapsible from '@/components/Collapsible';
import FixPanel from '@/components/FixPanel';
import { ExemplarCard } from '@/components/ExemplarCard';
import VerifyNote from '@/components/VerifyNote';
import { verifyFix } from '@/api/history';
import { announce } from '@/api/client';
import { cpgProvenance, cpgRuleName, isCpg } from '@/utils/joern';
import type { Finding, VerifyResult } from '@/types';

export default function FindingCard({ f, scanId, target, onApplied, onReverted }: { f: Finding; scanId?: string; target?: string; onApplied?: () => void; onReverted?: () => void }) {
  const [fixOpen, setFixOpen] = useState(false);
  // P8: re-verify THIS finding against the file as it is on disk right now (no LLM fix
  // needed - a fix made by hand in an editor counts). Preview-on-a-copy lives in the fix panel.
  const [verifying, setVerifying] = useState(false);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const v = f.verdict || {};
  const vName = v.verdict || 'Unverified';
  const exs = f.exemplars || [];
  const nEx = exs.length;

  const confN = v.confidence ?? 0;
  const confColor = confN >= 80 ? 'var(--danger)' : confN >= 50 ? 'var(--amber-500)' : 'var(--neutral-400)';
  const conf = v.available
    ? (
      <span className="confwrap">
        <span className="confmeter"><span className="conf-fill" style={{ width: Math.max(0, Math.min(100, confN)) + '%', background: confColor }}></span></span>
        <span className="conf-label">confidence {confN}</span>
      </span>
    )
    : null;

  const fixNote = v.fix_suggestion ? <span className="fixnote"><b>Suggested fix.</b> {v.fix_suggestion}</span> : null;
  const file = (f.path || '').split(/[\\/]/).pop() || '';
  const loc = file + ':' + f.line + (f.slice && f.slice.name ? ' · ' + f.slice.name + '()' : '');
  const ruleShort = String(f.rule_id || '').split('.').pop();
  const canFix = !!(v.available && f.slice && f.slice.code);
  const cpg = isCpg(f);
  const canVerifyLive = cpg && !!scanId && !!target && !!f.path && !!f.slice?.name && !!f.rule_id;

  const onVerifyLive = async () => {
    if (!canVerifyLive) return;
    setVerifying(true); setVerify(null);
    try {
      const r = await verifyFix({
        scan_id: scanId as string,
        path: f.path as string,
        function: (f.meta?.class ? f.meta.class + '.' : '') + (f.slice?.name as string),
        rule_id: f.rule_id as string,
      });
      setVerify(r);
      announce(r.ok ? (r.converged ? 'Re-verified: the locator no longer fires' : `Not verified: ${r.reason || 'the locator still fires'}`) : (r.error || 'Verification failed'));
    } catch (e) {
      setVerify({ ok: false, error: (e as Error).message || 'Verification failed' });
    } finally {
      setVerifying(false);
    }
  };

  return (
    <article className={'card finding' + (cpg ? ' is-cpg' : '')} data-tool={f.tool || ''}>
      <div className="fhead">
        <span className={'pill sev-' + esc(f.severity)}>{cap(f.severity || '')}</span>
        {cpg && <span className="pill mono cpg" title={['Located by Joern CPG analysis', cpgRuleName(f.rule_id), cpgProvenance(f)].filter(Boolean).join(' · ')}>CPG</span>}
        <span className="pill mono">{f.cwe_id || 'no CWE'}</span>
        <span className="pill mono" title={esc(f.rule_id)}>{ruleShort || ''}</span>
        <span className="floc">{loc}</span>
      </div>
      <h3 className="ftitle">{v.vuln_class || f.title || ''}</h3>
      <div className="fmsg">{f.message}</div>
      <div className="vrow"><span className={'pill ' + vClassOf(vName)}>{vName}</span>{conf}</div>
      {(v.explanation || fixNote) && <div className="explain">{v.explanation || ''}{fixNote}</div>}
      {(canFix || canVerifyLive) && (
        <div className="fixwrap" data-noprint>
          {canFix && !fixOpen && (
            <button className="btn fix-trigger" onClick={() => setFixOpen(true)}>
              <Icon id="ic-sparkles" /> Suggest a fix
            </button>
          )}
          {canVerifyLive && (
            <button className="btn verifybtn" onClick={onVerifyLive} disabled={verifying}
              title="Rebuild the code property graph on this file as it is now and check whether the locator still fires - use it after fixing the code yourself">
              {verifying ? 'Verifying with CPG…' : 'Verify with CPG'}
            </button>
          )}
          {cpg && !scanId && <span className="scope-empty">Verify with CPG needs a saved scan - sign in and scan again.</span>}
          {verify && <VerifyNote v={verify} />}
          {fixOpen && <FixPanel finding={f} scanId={scanId} target={target} onApplied={onApplied} onReverted={onReverted} />}
        </div>
      )}
      {f.slice && f.slice.code && (
        <Collapsible className="slice-coll" label="Vulnerable code">
          <div className="slice-meta">lines {String(f.slice.start_line)}-{String(f.slice.end_line)}</div>
          <pre className="code-dark">{f.slice.code}</pre>
        </Collapsible>
      )}
      <Collapsible defaultOpen label={`Grounded by ${nEx} real-world exemplar${nEx === 1 ? '' : 's'}`}>
        {nEx ? <div className="ex-grid">{exs.map((e, i) => <ExemplarCard e={e} key={i} />)}</div> : <div className="scope-empty">No matching exemplars found.</div>}
      </Collapsible>
    </article>
  );
}