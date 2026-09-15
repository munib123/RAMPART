import { esc, SEV_BAR_COLORS } from '@/utils/format';
import { scopeLabels } from '@/utils/scope';
import { cpgSummary } from '@/utils/joern';
import type { ScanReport } from '@/types';

export default function SummaryCard({ r }: { r: ScanReport }) {
  const findings = r.findings || [];
  const c = r.counts || {};
  const total = c.total ?? findings.length;
  const llmOn = !!(r.llm && r.llm.enabled);
  const files = new Set(findings.map((f) => f.path)).size;

  const vcount: Record<string, number> = {};
  findings.forEach((f) => {
    const v = (f.verdict && f.verdict.verdict) || 'Unverified';
    vcount[v] = (vcount[v] || 0) + 1;
  });
  const confirmed = vcount['Confirmed'] || 0;

  let headline: string, sub: string;
  if (!total) {
    headline = "You're all set.";
    sub = 'Nothing flagged in this path.';
  } else if (!llmOn) {
    headline = `${total} finding${total === 1 ? '' : 's'}, verdicts unverified`;
    sub = 'Set GEMINI_API_KEY in .env to enable grounded verdicts, confidence, and suggested fixes.';
  } else {
    headline = confirmed
      ? `${confirmed} confirmed issue${confirmed === 1 ? '' : 's'} need${confirmed === 1 ? 's' : ''} attention`
      : 'No confirmed issues. Review the findings below';
    const parts = ['Confirmed', 'Likely', 'Informational', 'False positive']
      .filter((k) => vcount[k]).map((k) => `${vcount[k]} ${k.toLowerCase()}`);
    const rest = Object.keys(vcount).filter((k) => !['Confirmed', 'Likely', 'Informational', 'False positive'].includes(k))
      .map((k) => `${vcount[k]} ${k.toLowerCase()}`);
    sub = `${total} finding${total === 1 ? '' : 's'} across ${files} file${files === 1 ? '' : 's'}: ${parts.concat(rest).join(', ')}.`;
  }

  const modelPill = llmOn
    ? `<span class="pill mono sm">${esc(r.llm!.model || '')}</span>`
    : '<span class="pill mono warn sm">LLM off</span>';
  // Provenance: the CPG phase ran alongside the scanner (additive, never an alternative).
  const cpg = cpgSummary(r.joern, findings);
  const cpgPill = cpg.used
    ? `<span class="pill mono cpg sm" title="Joern CPG phase ran in ${esc(cpg.mode || 'script')} mode${cpg.elapsedS ? ' · ' + esc(cpg.elapsedS) + 's' : ''}${cpg.pack ? ' · vocabulary pack ' + esc(cpg.pack) : ''}">+ CPG</span>`
    : '';
  const pills = `<span class="pill mono sm">${esc(r.scanner || '')}</span>${cpgPill}${modelPill}<span class="pill mono sm">${esc(String(r.elapsed_s ?? ''))}s</span>`;

  // "N of these came from Joern CPG analysis, M confirmed" - or why the phase did not run.
  let cpgNote: { cls: string; text: string } | null = null;
  if (cpg.used) {
    const n = cpg.candidates;
    if (n) {
      const judged = [
        cpg.confirmed ? `${cpg.confirmed} confirmed` : '',
        cpg.likely ? `${cpg.likely} likely` : '',
        cpg.cleared ? `${cpg.cleared} cleared by the LLM` : '',
      ].filter(Boolean).join(', ');
      cpgNote = { cls: '', text: `${n} of these came from Joern CPG analysis (logic bugs the pattern scanner cannot see)${judged ? ': ' + judged : ''}.` };
    } else {
      cpgNote = { cls: 'quiet', text: 'Joern CPG analysis ran and located no logic-bug candidates (IDOR, mass assignment, unchecked quantity, TOCTOU).' };
    }
    if (cpg.broken.length) cpgNote.text += ` Rule${cpg.broken.length === 1 ? '' : 's'} ${cpg.broken.join(', ')} did not run.`;
    if (cpg.pack) cpgNote.text += ` Vocabulary: ${cpg.pack}${cpg.packNote ? ' (' + cpg.packNote + ')' : ''}.`;
  } else if (cpg.reason) {
    cpgNote = { cls: 'quiet', text: `CPG phase skipped: ${cpg.reason}.` };
  }

  const segs = ['critical', 'high', 'medium', 'low'].filter((s) => c[s as keyof typeof c]);
  const bar = total
    ? '<div class="sevbar">' + segs.map((s) =>
      `<span style="width:${((Number(c[s as keyof typeof c]) || 0) / total) * 100}%;background:${SEV_BAR_COLORS[s]}"></span>`).join('') + '</div>'
    : '';
  const items = segs.map((s) =>
    `<span class="legend-item"><span class="ldot" style="background:${SEV_BAR_COLORS[s]}"></span>${c[s as keyof typeof c]} ${s}</span>`).join('');
  const scope = scopeLabels(r.scope).map((l) => `<span class="scope-pill">${esc(l)}</span>`).join('');
  const legend = total ? `<div class="legend">${items}${scope}</div>` : '';

  return (
    <div className="card summary-card">
      <div className="sum-row">
        <span className="sum-label">Scan summary</span>
        <span className="sum-pills" dangerouslySetInnerHTML={{ __html: pills }} />
      </div>
      <h2 className="sum-headline">{headline}</h2>
      <p className="sum-sub">{sub}</p>
      <div dangerouslySetInnerHTML={{ __html: bar + legend }} />
      {cpgNote && (
        <div className={'cpg-callout ' + cpgNote.cls} data-testid="cpg-callout">
          <span className="pill mono cpg sm">CPG</span>
          <span>{cpgNote.text}</span>
        </div>
      )}
    </div>
  );
}