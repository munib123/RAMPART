import { useState, type FormEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';
import { announce } from '@/api/client';
import { Icon } from '@/components/Icons';

export default function Auth() {
  const [params] = useSearchParams();
  const [mode, setMode] = useState<'login' | 'signup'>(params.get('mode') === 'signup' ? 'signup' : 'login');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const { signIn, signUp } = useAuth();
  const navigate = useNavigate();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setNote('');
    const trimmed = name.trim();
    if (mode === 'signup' && !trimmed) { setNote('Enter your name.'); return; }
    if (!email || !/.+@.+\..+/.test(email)) { setNote('Enter a valid email address.'); return; }
    if (password.length < 8) { setNote('Password must be at least 8 characters.'); return; }
    setBusy(true);
    try {
      const user = mode === 'signup' ? await signUp(trimmed, email, password) : await signIn(email, password);
      announce('Signed in as ' + (user.name || user.email));
      navigate('/setup');
    } catch (err) {
      setNote((err as Error).message || 'Sign-in failed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="view auth-page" id="view-auth">
      <div className="auth-shell">
        <aside className="auth-panel">
          <div className="auth-panel-brand">
            <span className="auth-panel-logo"><Icon id="rp-logo" svgClass="logo-lg" /></span>
            <span className="auth-panel-word">RAMPART</span>
          </div>

          <div className="auth-panel-mid">
            <h1 className="auth-panel-title">Verified findings,<br />ranked for your codebase.</h1>
            <p className="auth-panel-sub">RAMPART scans your code, grounds every finding in real-world disclosures, and verifies it with an LLM — one batched call per scan.</p>

            <ul className="auth-feats">
              <li>
                <span className="auth-feat-ic"><Icon id="ic-scan" /></span>
                Scan with semgrep or bandit
              </li>
              <li>
                <span className="auth-feat-ic"><Icon id="ic-ground" /></span>
                Grounded in HackerOne &amp; Nuclei disclosures
              </li>
              <li>
                <span className="auth-feat-ic"><Icon id="ic-verify" /></span>
                LLM-verified verdicts &amp; one-click fixes
              </li>
            </ul>
          </div>

          <div className="auth-panel-foot">
            <div className="auth-stats">
              <div className="auth-stat">
                <span className="mono">42k+</span>
                <span>disclosures indexed</span>
              </div>
              <div className="auth-stat">
                <span className="mono">2</span>
                <span>grounding sources</span>
              </div>
              <div className="auth-stat">
                <span className="mono">1</span>
                <span>LLM call per scan</span>
              </div>
            </div>

            <div className="auth-panel-pills" aria-hidden="true">
              <span className="mono">scan</span><span className="auth-arrow">→</span>
              <span className="mono">extract</span><span className="auth-arrow">→</span>
              <span className="mono">ground</span><span className="auth-arrow">→</span>
              <span className="mono">verify</span>
            </div>
          </div>
        </aside>

        <div className="auth-main">
          <div className="auth-mobile-brand">
            <Icon id="rp-logo" svgClass="logo-md" />
            <span className="auth-mobile-word">RAMPART</span>
          </div>

          <div className="auth-inner">
            <div className="auth-head">
              <h2 className="auth-head-title">{mode === 'login' ? 'Welcome back' : 'Create your account'}</h2>
              <p className="auth-head-sub">
                {mode === 'login'
                  ? 'Sign in to save scans to your history and contribute anonymised research.'
                  : 'Start scanning in under a minute — history and research included.'}
              </p>
            </div>

            <div className="auth-tabs" role="tablist" aria-label="Sign in or create account">
              <button type="button" className={'auth-tab ' + (mode === 'login' ? 'is-on' : '')} data-mode="login" role="tab" aria-selected={mode === 'login'} onClick={() => setMode('login')}>Sign in</button>
              <button type="button" className={'auth-tab ' + (mode === 'signup' ? 'is-on' : '')} data-mode="signup" role="tab" aria-selected={mode === 'signup'} onClick={() => setMode('signup')}>Create account</button>
            </div>

            <form className="auth-form" onSubmit={submit} noValidate>
              {mode === 'signup' && (
                <div className="field">
                  <label className="field-label" htmlFor="authName">Name</label>
                  <span className="auth-input">
                    <Icon id="ic-user" svgClass="auth-input-ic" />
                    <input type="text" id="authName" autoComplete="name" placeholder="Ada Lovelace" maxLength={80} value={name} onChange={(e) => setName(e.target.value)} />
                  </span>
                </div>
              )}
              <div className="field">
                <label className="field-label" htmlFor="authEmail">Email</label>
                <span className="auth-input">
                  <Icon id="ic-mail" svgClass="auth-input-ic" />
                  <input type="email" id="authEmail" autoComplete="email" placeholder="you@example.com" required value={email} onChange={(e) => setEmail(e.target.value)} />
                </span>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="authPassword">Password</label>
                <span className="auth-input">
                  <Icon id="ic-lock" svgClass="auth-input-ic" />
                  <input type={showPw ? 'text' : 'password'} id="authPassword" autoComplete={mode === 'signup' ? 'new-password' : 'current-password'} placeholder="at least 8 characters" required minLength={8} value={password} onChange={(e) => setPassword(e.target.value)} />
                  <button type="button" className="auth-eye" aria-label={showPw ? 'Hide password' : 'Show password'} title={showPw ? 'Hide password' : 'Show password'} onClick={() => setShowPw((v) => !v)}>
                    <Icon id={showPw ? 'ic-eye-off' : 'ic-eye'} />
                  </button>
                </span>
              </div>
              <div className="form-note" role="alert">{note}</div>
              <button className="btn btn-primary btn-block btn-auth" type="submit" disabled={busy}>
                {busy ? (mode === 'signup' ? 'Creating account…' : 'Signing in…') : (mode === 'signup' ? 'Create account' : 'Sign in')}
              </button>
            </form>

            <p className="auth-foot">
              <Icon id="ic-lock" svgClass="auth-foot-ic" />
              Protected with bcrypt &amp; JWT — credentials never leave this app.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}