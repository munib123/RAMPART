import { useState, type FormEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';
import { announce } from '@/api/client';
import { Icon } from '@/components/Icons';

export default function Auth() {
  const [params] = useSearchParams();
  const [mode, setMode] = useState<'login' | 'signup'>(params.get('mode') === 'signup' ? 'signup' : 'login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const { signIn, signUp } = useAuth();
  const navigate = useNavigate();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setNote('');
    if (!email || !/.+@.+\..+/.test(email)) { setNote('Enter a valid email address.'); return; }
    if (password.length < 8) { setNote('Password must be at least 8 characters.'); return; }
    setBusy(true);
    try {
      const user = mode === 'signup' ? await signUp(email, password) : await signIn(email, password);
      announce('Signed in as ' + user.email);
      navigate('/setup');
    } catch (err) {
      setNote((err as Error).message || 'Sign-in failed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="view view-center" id="view-auth" style={{ display: 'flex', flex: 1 }}>
      <div className="auth-card card">
        <div className="auth-brand">
          <Icon id="rp-logo" svgClass="logo-xl" />
          <div className="auth-title">RAMPART account</div>
          <div className="auth-sub">Sign in to save scans to your history and contribute anonymised research.</div>
        </div>

        <div className="auth-tabs" role="tablist" aria-label="Sign in or create account">
          <button type="button" className={'auth-tab ' + (mode === 'login' ? 'is-on' : '')} data-mode="login" role="tab" aria-selected={mode === 'login'} onClick={() => setMode('login')}>Sign in</button>
          <button type="button" className={'auth-tab ' + (mode === 'signup' ? 'is-on' : '')} data-mode="signup" role="tab" aria-selected={mode === 'signup'} onClick={() => setMode('signup')}>Create account</button>
        </div>

        <form className="auth-form" onSubmit={submit} noValidate>
          <label className="field">
            <span className="field-label">Email</span>
            <input type="email" id="authEmail" autoComplete="email" placeholder="you@example.com" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <label className="field">
            <span className="field-label">Password</span>
            <input type="password" id="authPassword" autoComplete={mode === 'signup' ? 'new-password' : 'current-password'} placeholder="at least 8 characters" required minLength={8} value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
          <div className="form-note" role="alert">{note}</div>
          <button className="btn btn-primary btn-block" type="submit" disabled={busy}>{busy ? (mode === 'signup' ? 'Creating account…' : 'Signing in…') : (mode === 'signup' ? 'Create account' : 'Sign in')}</button>
        </form>
      </div>
    </section>
  );
}