import { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import SummaryCard from '@/components/SummaryCard';
import FindingCard from '@/components/FindingCard';
import PlanLimitCard from '@/components/PlanLimitCard';
import { announce } from '@/api/client';
import { revertFix } from '@/api/history';
import { Icon } from '@/components/Icons';
import type { PlanLimitPayload, ScanReport } from '@/types';

export default function Report() {
  const location = useLocation();
  const navigate = useNavigate();
  const state = (location.state || {}) as { report?: ScanReport; path?: string };
  const report = state.report;
  const path = state.path || report?.target || '';
  const [applied, setApplied] = useState(false);
  const [reverting, setReverting] = useState(false);

  useEffect(() => {
    if (report) {
      announce('Scan complete: ' + ((report.counts && report.counts.total) ?? (report.findings || []).length) + ' findings');
    }
  }, [report]);

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

  const onExport = () => {
    // expand all collapsibles, then print (native)
    document.querySelectorAll('#view-report .coll').forEach((c) => {
      c.classList.add('is-open');
      const b = c.querySelector('[data-coll]');
      if (b) b.setAttribute('aria-expanded', 'true');
    });
    setTimeout(() => window.print(), 120);
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
              findings.map((f, i) => <FindingCard f={f} key={i} scanId={report.scan_id} target={report.target} onApplied={() => setApplied(true)} />)
            )}
          </>
        )}
      </div>
    </section>
  );
}