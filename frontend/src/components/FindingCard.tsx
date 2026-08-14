import { useState } from 'react';
import { cap, esc, vClassOf } from '@/utils/format';
import { Icon } from '@/components/Icons';
import Collapsible from '@/components/Collapsible';
import FixPanel from '@/components/FixPanel';
import { ExemplarCard } from '@/components/ExemplarCard';
import type { Finding } from '@/types';

export default function FindingCard({ f, scanId, target, onApplied, onReverted }: { f: Finding; scanId?: string; target?: string; onApplied?: () => void; onReverted?: () => void }) {
  const [fixOpen, setFixOpen] = useState(false);
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

  return (
    <article className="card finding">
      <div className="fhead">
        <span className={'pill sev-' + esc(f.severity)}>{cap(f.severity || '')}</span>
        <span className="pill mono">{f.cwe_id || 'no CWE'}</span>
        <span className="pill mono" title={esc(f.rule_id)}>{ruleShort || ''}</span>
        <span className="floc">{loc}</span>
      </div>
      <h3 className="ftitle">{v.vuln_class || f.title || ''}</h3>
      <div className="fmsg">{f.message}</div>
      <div className="vrow"><span className={'pill ' + vClassOf(vName)}>{vName}</span>{conf}</div>
      {(v.explanation || fixNote) && <div className="explain">{v.explanation || ''}{fixNote}</div>}
      {canFix && (
        <div className="fixwrap" data-noprint>
          {!fixOpen && (
            <button className="btn fix-trigger" onClick={() => setFixOpen(true)}>
              <Icon id="ic-sparkles" /> Suggest a fix
            </button>
          )}
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