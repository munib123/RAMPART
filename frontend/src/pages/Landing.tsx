import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';
import { useHealth } from '@/context/HealthContext';
import { esc, fmtN } from '@/utils/format';
import { Icon } from '@/components/Icons';

function PipelineNode({ n, icon, name, cap, chip }: { n: string; icon: string; name: string; cap: string; chip: string }) {
  return (
    <div className="pnode">
      <span className="pnode-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <use href={`#${icon}`} />
        </svg>
      </span>
      <div className="pnode-name">{n} · {name}</div>
      <div className="pnode-cap">{cap}</div>
      <span className="pnode-chip">{chip}</span>
    </div>
  );
}

function Connector() {
  return (
    <div className="pconn" aria-hidden="true">
      <svg width="44" height="16" viewBox="0 0 44 16" fill="none">
        <line className="flow" x1="2" y1="8" x2="34" y2="8" stroke="var(--blue-300)" strokeWidth="2" strokeLinecap="round" strokeDasharray="2 6" />
        <path d="m34 3 6 5-6 5" stroke="var(--blue-300)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </div>
  );
}

export default function Landing() {
  const navigate = useNavigate();
  const { token } = useAuth();
  const health = useHealth();

  const cols = health?.collections || [];
  const totalVecs = cols.reduce((n, c) => n + (typeof c.vectors === 'number' ? c.vectors : 0), 0);
  const disclosures = totalVecs ? `${fmtN(totalVecs)} disclosures` : 'real disclosures';
  const model = health?.llm_enabled ? (health.model || 'LLM') : 'LLM off';

  const scannerStrip = health
    ? `<span class="strip-pill"><span class="dot"></span>${esc(health.scanner)} · ${health.scanner === 'semgrep' ? 'multi-language' : 'python-only'}</span>`
    : '';
  const llmStrip = health
    ? health.llm_enabled
      ? `<span class="strip-pill"><span class="dot"></span>llm · ${esc(health.model || '')}</span>`
      : `<span class="strip-pill warn"><span class="dot"></span>llm · off</span>`
    : '';
  const colPills = cols.map((c) =>
    `<span class="strip-pill">${esc(String(c.collection || '').replace('rampart_', '').replace('_minilm', ''))} · ${fmtN(c.vectors)}</span>`).join('');

  const start = () => {
    if (!token) { navigate('/auth?mode=signup'); return; }
    navigate('/setup');
  };

  return (
    <section className="view view-center" id="view-landing">
      <div className="hero">
        <Icon id="rp-logo" svgClass="logo-xl" />
        <div className="eyebrow">SCAN &middot; GROUND &middot; VERIFY</div>
        <h1 className="hero-title">Findings you can trust.</h1>
        <p className="hero-sub">RAMPART scans your code, grounds every finding in real disclosed vulnerabilities, and has an LLM verify each one: confirmed, explained, with a suggested fix.</p>
        <div className="hero-cta">
          <button className="btn btn-primary btn-lg" onClick={start}>Start a scan</button>
        </div>
      </div>

      <div className="pipeline">
        <PipelineNode n="1" icon="ic-scan" name="Scan" cap="Static analysis flags candidate weaknesses; a code property graph locates the logic bugs it cannot." chip={health?.scanners?.joern?.available ? 'semgrep · bandit · joern CPG' : 'semgrep · bandit'} />
        <Connector />
        <PipelineNode n="2" icon="ic-ground" name="Ground" cap="Each finding is matched to real disclosed vulnerabilities, filtered by CWE." chip={disclosures} />
        <Connector />
        <PipelineNode n="3" icon="ic-verify" name="Verify" cap="An LLM confirms each finding, rates confidence, and suggests a fix." chip={model} />
      </div>

      <div className="status-strip" dangerouslySetInnerHTML={{ __html: scannerStrip + llmStrip + colPills }} />
      <div className="footnote">Runs on localhost · fixes are suggested as diffs, never auto-applied</div>
    </section>
  );
}