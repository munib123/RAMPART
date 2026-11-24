import { useCallback, useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import SummaryCard from '@/components/SummaryCard';
import FindingCard from '@/components/FindingCard';
import PlanLimitCard from '@/components/PlanLimitCard';
import { announce } from '@/api/client';
import { useAuth } from '@/context/AuthContext';
import { revertFix } from '@/api/history';
import { Icon } from '@/components/Icons';
import { loadReport, saveReport } from '@/utils/reportStore';
import type { PlanLimitPayload, ScanReport } from '@/types';

// A 60-finding report renders the first 40 cards, then 40 more per click. Export expands all
// (below) so a printed/PDF report is never truncated.
const PAGE = 40;

export default function Report() {
  const location = useLocation();
  const navigate = useNavigate();
  const { token } = useAuth();
  const state = (location.state || {}) as { report?: ScanReport; path?: string };
  const stateReport = state.report;
  const statePath = state.path;
  // A refresh on /report has no router state: fall back to the last successful report saved in
  // this tab. `useState` runs the (synchronous) read once per mount.
  const [persisted] = useState(() => (stateReport ? null : loadReport()));
  const report = stateReport || persisted?.report;
  const path = statePath || report?.target || persisted?.path || '';

  const [applied, setApplied] = useState(false);
  const [reverting, setReverting] = useState(false);
  const [visible, setVisible] = useState(PAGE);

  // Persist a successful report so a refresh restores it; sign-out clears it (AuthContext).
  useEffect(() => {
    if (stateReport && stateReport.ok) saveReport(stateReport, statePath);
  }, [stateReport, statePath]);

  useEffect(() => {
    setVisible(PAGE);
    setApplied(false);
  }, [report]);

  useEffect(() => {
    if (report) {
      announce('Scan complete: ' + ((report.counts && report.counts.total) ?? (report.findings || []).length) + ' findings');
    }
  }, [report]);

  // Stable callbacks so the memoized FindingCard list does not re-render on banner toggles.
  const onApplied = useCallback(() => setApplied(true), []);
  const onReverted = useCallback(() => setApplied(false), []);

  const onRevertAll = async () => {
    if (!report?.scan_id || !report.target) return;
    if (!window.confirm(`Revert ${report.target} to its state at first apply? All applied fixes are undone.`)) return;
    setReverting(true);
    try {
      const r = await revertFix({ scan_id: report.scan_id, target: report.target });
      if (r.ok) {
        setApplied(false);
        announce('All changes reverted — code restored');
      } else {
        announce(r.error || 'Revert failed');
      }
    } catch (e) {
      announce((e as Error).message || 'Revert failed');
    } finally {
      setReverting(false);
    }
  };

  if (!report) {
    return (
      <section className="view" id="view-report">
        <div className="report-bar">
          <button className="btn" onClick={() => navigate('/setup')} data-noprint><Icon id="ic-arrow-left" /> New scan</button>
        </div>
        <div className="card"><div className="warn-banner">No report loaded. Run a scan first.</div></div>
      </section>
    );
  }

  const findings = report.findings || [];
  // Signed in, but the scan came back without a scan_id: the token had expired when the scan
  // ran, so it was not saved and Apply / Verify are unavailable. Say so instead of hiding them.
  const unsaved = !!token && report.ok && !report.scan_id && !report.code;

  // Plan-limit passthrough from POST /api/scan (402) -> upsell card, not an error dump.
  if (report.code === 'plan_limit') {
    const payload: PlanLimitPayload = { code: 'plan_limit', kind: 'scan', plan: report.plan, used: report.used, limit: report.limit };
    return (
      <section className="view" id="view-report">
        <div className="report-bar">
          <button className="btn" onClick={() => navigate('/setup')} data-noprint><Icon id="ic-arrow-left" /> New scan</button>
        </div>
        <PlanLimitCard limit={payload} label="Upgrade to keep scanning" />
      </section>
    );
  }

  const shown = findings.slice(0, visible);
  const remaining = findings.length - shown.length;

  const onExport = () => {
    // Export must include every finding, not just the pages shown: expand first, then open the
    // print dialog on the next tick once React has rendered the remaining cards.
    setVisible(findings.length);
    setTimeout(() => {
      document.querySelectorAll('#view-report .coll').forEach((c) => {
        c.classList.add('is-open');
        const b = c.querySelector('[data-coll]');
        if (b) b.setAttribute('aria-expanded', 'true');
      });
      window.print();
    }, 200);
  };

  return (
    <section className="view" id="view-report">
      <div className="report-bar">
        <button className="btn" onClick={() => navigate('/setup')} data-noprint><Icon id="ic-arrow-left" /> New scan</button>
        <span className="report-target">{path}</span>
        <button className="btn" onClick={onExport} data-noprint><Icon id="ic-printer" /> Export report</button>
      </div>
      <div id="result">
        {!report.ok ? (
          <div className="card"><div className="warn-banner">Scan failed. {report.error || ''}</div></div>
        ) : (
          <>
            <SummaryCard r={report} />
            {unsaved && (
              <div className="card warn-banner unsaved-banner" data-noprint>
                <b>This scan was not saved</b> - your session had expired when it ran, so <b>Suggest a fix</b> works but
                <b> Apply</b>, <b>Revert</b> and <b>Verify with CPG</b> are unavailable for it.
                <button className="btn btn-xs" onClick={() => navigate('/auth')}>Sign in again</button> and re-scan.
              </div>
            )}
            {applied && report.scan_id && report.target && (
              <div className="card applied-banner" data-noprint>
                <div><b>Fix applied to the codebase.</b> A snapshot of <span className="mono">{path}</span> was kept before the change.</div>
                <button className="btn btn-xs revertbtn" onClick={onRevertAll} disabled={reverting}>
                  {reverting ? 'Reverting…' : 'Revert all changes'}
                </button>
              </div>
            )}
            {!findings.length ? (
              <div className="card empty-card"><div className="big">You're all set.</div><div className="sub">Nothing flagged in this path.</div></div>
            ) : (
              <>
                {shown.map((f, i) => (
                  <FindingCard
                    f={f}
                    key={`${f.path}:${f.line}:${f.cwe_id}:${f.rule_id}:${i}`}
                    scanId={report.scan_id}
                    target={report.target}
                    onApplied={onApplied}
                    onReverted={onReverted}
                  />
                ))}
                {remaining > 0 && (
                  <div className="show-more" data-noprint>
                    <button className="btn" onClick={() => setVisible((v) => Math.min(v + PAGE, findings.length))}>
                      Show {Math.min(PAGE, remaining)} more ({remaining} remaining)
                    </button>
                  </div>
                )}
              </>
            )}
          </>
        )}
      </div>
    </section>
  );
}
