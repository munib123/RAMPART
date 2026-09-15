import { useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useHealth } from '@/context/HealthContext';
import { useScan } from '@/hooks/useScan';
import { cpgPhaseRuns } from '@/utils/joern';
import { Icon } from '@/components/Icons';

export default function Scanning() {
  const location = useLocation();
  const navigate = useNavigate();
  const health = useHealth();
  const state = (location.state || {}) as { path?: string; scanner?: string; scope?: Record<string, unknown> };
  const path = state.path || '';
  const scanner = state.scanner || 'auto';
  const scope = state.scope || {};

  const { elapsedMs, percent, longNote, report, error, stageRows, start, cancel } = useScan({
    path,
    scanner,
    scope,
    model: health?.model,
    activeScanner: health?.scanner,
    cpg: cpgPhaseRuns(health),
  });

  // Start once when mounted.
  useEffect(() => { start(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

  // When a report or an error arrives, move to the Report view.
  useEffect(() => {
    if (report) {
      navigate('/report', { state: { report, path } });
    }
  }, [report, path, navigate]);

  return (
    <section className="view" id="view-scanning">
      <div className="scancard">
        <div className="scan-head">
          <h3>Scanning</h3>
          <span className="scan-target" id="scanTarget">{path}</span>
          <span className="scan-elapsed" id="scanElapsed">{(elapsedMs / 1000).toFixed(1)}s</span>
        </div>
        <div className="track" id="scanTrack" role="progressbar" aria-label="Scan progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(percent / 5) * 5}>
          <div className="track-fill" id="progressFill" style={{ width: percent.toFixed(1) + '%' }}></div>
        </div>
        <div className="stage-list" id="stageList">
          {stageRows.map((row, i) => (
            <div className={'stage-row ' + (row.state === 'done' ? 'is-done' : row.state === 'active' ? 'is-active' : 'is-pending')} key={i}>
              <span className="stage-circle">
                {row.state === 'done' ? <Icon id="ic-check" /> : row.state === 'active' ? <span className="stage-spinner"></span> : <span>{i + 1}</span>}
              </span>
              <div className="stage-main">
                <div className="stage-name">{row.name}</div>
                <div className="stage-note">{row.note}</div>
              </div>
              <span className="stage-time">{row.time || ''}</span>
            </div>
          ))}
        </div>
        <div className="scan-foot">
          <span id="scanFootNote">{longNote ? 'Still working. Large codebases can take several minutes.' : error ? 'Scan failed.' : 'Verdicts arrive in one batched LLM call.'}</span>
          <button className="btn btn-ghostline" id="cancelScanBtn" onClick={() => { cancel(); navigate('/setup'); }}>Cancel</button>
        </div>
      </div>
    </section>
  );
}