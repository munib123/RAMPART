import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';
import { useHealth } from '@/context/HealthContext';
import { esc } from '@/utils/format';
import { Icon } from '@/components/Icons';

export default function AppBar() {
  const { user, token, signOut } = useAuth();
  const health = useHealth();
  const navigate = useNavigate();

  const scannerPill = health
    ? `<span class="pill mono"><span class="dot"></span>${esc(health.scanner)}</span>`
    : `<span class="pill bad"><span class="dot"></span>connecting to backend…</span>`;
  const llmPill = health
    ? health.llm_enabled
      ? `<span class="pill ok"><span class="dot"></span>LLM · ${esc(health.model || '')}</span>`
      : `<span class="pill warn"><span class="dot"></span>LLM off</span>`
    : '';

  return (
    <header className="appbar" data-noprint>
      <button type="button" className="brand" onClick={() => navigate('/')} title="Home" aria-label="RAMPART home">
        <Icon id="rp-logo" svgClass="logo" />
        <span className="wordmark">RAMPART</span>
        <span className="poc-pill">POC</span>
      </button>
      <div className="appbar-status" dangerouslySetInnerHTML={{ __html: scannerPill + llmPill }} />
      <div className="appbar-account">
        {token && user ? (
          <>
            <span className="account-pill"><span className="dot"></span><span className="mail">{user.email}</span></span>
            <button className="account-btn" onClick={() => navigate('/history')} title="View saved scans">History</button>
            <button className="account-btn" onClick={signOut} title="Sign out">Sign out</button>
          </>
        ) : (
          <button className="account-btn" onClick={() => navigate('/auth')}>Sign in</button>
        )}
      </div>
    </header>
  );
}