import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';
import { useHealth } from '@/context/HealthContext';
import { loadProfile, updateName, changePassword } from '@/api/profile';
import { announce } from '@/api/client';
import { initialsOf } from '@/components/ProfileMenu';
import { Icon } from '@/components/Icons';
import type { PlanInfo } from '@/types';

function UsageBar({ used, limit, kind, hint }: { used: number; limit: number; kind: string; hint?: string }) {
  const pct = limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0;
  const left = limit - used;
  const tone = left <= 0 ? 'used-up' : left <= Math.max(1, Math.round(limit * 0.2)) ? 'used-low' : 'used-ok';
  return (
    <div className="usage">
      <div className="usage-row">
        <span className="usage-kind">{kind}</span>
        <span className="usage-count">{used} / {limit}</span>
      </div>
      <div className="usage-bar"><span className={'usage-fill ' + tone} style={{ width: pct + '%' }}></span></div>
      {hint && <span className="usage-hint">{hint}</span>}
    </div>
  );
}

function Field({
  id, type, value, onChange, icon, autoComplete, placeholder, toggle, maxLength,
}: {
  id: string; type: string; value: string; onChange: (v: string) => void;
  icon: string; autoComplete?: string; placeholder?: string; toggle?: () => void; maxLength?: number;
}) {
  return (
    <div className={'prof-field' + (value ? ' has-value' : '')}>
      <span className="prof-field-ic" aria-hidden="true"><Icon id={icon} /></span>
      <input
        id={id} type={type} value={value} spellCheck={false} autoComplete={autoComplete}
        placeholder={placeholder} maxLength={maxLength} onChange={(e) => onChange(e.target.value)}
      />
      {toggle && (
        <button type="button" className="prof-field-eye" onClick={toggle} aria-label="Toggle visibility" tabIndex={-1}>
          <Icon id={type === 'password' ? 'ic-eye' : 'ic-eye-off'} />
        </button>
      )}
    </div>
  );
}

export default function Profile() {
  const { user, token, refreshUser } = useAuth();
  const health = useHealth();
  const navigate = useNavigate();
  const [info, setInfo] = useState<PlanInfo | null>(null);
  const [name, setName] = useState(user?.name || '');
  const [nameSaving, setNameSaving] = useState(false);
  const [nameSaved, setNameSaved] = useState(false);
  const [nameErr, setNameErr] = useState(false);
  const [oldPw, setOldPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [pwMsg, setPwMsg] = useState('');
  const [pwErr, setPwErr] = useState('');
  const [pwBusy, setPwBusy] = useState(false);

  const load = useCallback(async () => {
    if (!token || !health?.db_enabled) return;
    try {
      const r = await loadProfile();
      setInfo(r.usage);
    } catch { /* backend down transient */ }
  }, [token, health?.db_enabled]);

  useEffect(() => { void load(); }, [load]);

  if (!token || !user) return null; // RequireAuth guards; brief blank while auth resolves

  const dbOff = !health?.db_enabled;

  const onSaveName = async () => {
    const n = name.trim();
    if (!n) { announce('Name cannot be empty'); return; }
    setNameSaving(true);
    setNameErr(false);
    try {
      const r = await updateName(n);
      setInfo(r.usage);
      await refreshUser();
      setNameSaved(true);
      announce('Profile updated');
      setTimeout(() => setNameSaved(false), 2000);
    } catch {
      setNameErr(true);
      announce('Could not update name');
    } finally {
      setNameSaving(false);
    }
  };

  const onPw = async () => {
    setPwErr(''); setPwMsg('');
    if (newPw.length < 8) { setPwErr('New password must be at least 8 characters.'); return; }
    if (newPw !== confirmPw) { setPwErr('New passwords do not match.'); return; }
    setPwBusy(true);
    try {
      await changePassword(oldPw, newPw);
      setOldPw(''); setNewPw(''); setConfirmPw('');
      setPwMsg('Password changed.');
      announce('Password changed');
    } catch (e) {
      setPwErr((e as Error).message || 'Could not change password');
    } finally {
      setPwBusy(false);
    }
  };

  /* Persistent back: go one page back in history, else fall back home. */
  const goBack = () => {
    if (window.history.length > 1) navigate(-1);
    else navigate('/');
  };

  const plan = info?.plan || user?.plan || 'free';
  const planLabel = info?.label || plan;

  const scansLeft = Math.max(0, (info?.scans.limit ?? 0) - (info?.scans.used ?? 0));
  const planHint =
    plan === 'free'
      ? scansLeft <= 0
        ? 'Out of free scans — upgrade to keep scanning.'
        : 'Upgrade for more scans and fixes.'
      : scansLeft <= 0
        ? 'Plan limit reached this period.'
        : 'Looking good — room to keep going.';

  return (
    <section className="view" id="view-profile">
      <div className="setup-head backbar">
        <button className="btn backbtn" onClick={goBack} aria-label="Go back" title="Go back">
          <Icon id="ic-arrow-left" />
        </button>
        <div>
          <h2>Your profile</h2>
          <p>Account details, your plan and how much of it you've used.</p>
        </div>
      </div>

      {dbOff ? (
        <div className="card"><div className="warn-banner">Persistence is disabled — no DATABASE_URL. Profile and plan features are unavailable.</div></div>
      ) : (
        <>
          <div className="profile-hero">
            <div className="profile-hero-avatar" aria-hidden="true">{initialsOf(user || { name, email: '' })}</div>
            <div className="profile-hero-info">
              <div className="profile-hero-name">{user?.name || name}</div>
              <div className="profile-hero-mail">{user?.email}</div>
              <span className={'pill plan-pill plan-' + plan}>{planLabel}</span>
            </div>
            <div className="profile-hero-cta">
              <div className="profile-hero-quick">10 scans &amp; 5 fixes included</div>
              <button className="btn btn-primary" onClick={() => navigate('/pricing')}>
                Manage plan
                <Icon id="ic-chevron" />
              </button>
            </div>
          </div>

          <div className="profile-grid">
            <div className="card">
              <div className="scard-head">
                <div className="scard-label">Account</div>
              </div>
              <label className="field-label" htmlFor="profName">Display name</label>
              <div className="prof-row">
                <Field id="profName" type="text" icon="ic-user" value={name} onChange={setName} maxLength={80} />
                <button className="btn btn-primary" onClick={onSaveName} disabled={nameSaving || !name.trim() || name.trim() === (user?.name || '')}>
                  {nameSaving ? 'Saving…' : (nameSaved ? 'Saved' : 'Save')}
                </button>
              </div>
              {nameErr && <div className="err-note" role="alert">Could not update your name.</div>}
              <div className="scard-note">Your display name is shown to you in the app bar and on reports.</div>
            </div>

            <div className="card">
              <div className="scard-head">
                <div className="scard-label">Change password</div>
              </div>
              <div className="pswd-grid">
                <div>
                  <label className="field-label" htmlFor="oldPw">Current password</label>
                  <Field icon="ic-lock" id="oldPw" type={showPw ? 'text' : 'password'} value={oldPw} onChange={setOldPw} autoComplete="current-password" />
                </div>
                <div>
                  <label className="field-label" htmlFor="newPw">New password</label>
                  <Field icon="ic-lock" id="newPw" type={showPw ? 'text' : 'password'} value={newPw} onChange={setNewPw} autoComplete="new-password" toggle={() => setShowPw((s) => !s)} />
                </div>
                <div>
                  <label className="field-label" htmlFor="confirmPw">Confirm new password</label>
                  <Field icon="ic-lock" id="confirmPw" type={showPw ? 'text' : 'password'} value={confirmPw} onChange={setConfirmPw} autoComplete="new-password" />
                </div>
              </div>
              {pwMsg && <div className="ok-note" role="status">{pwMsg}</div>}
              {pwErr && <div className="err-note" role="alert">{pwErr}</div>}
              <div className="profile-action">
                <button className="btn btn-primary" onClick={onPw} disabled={pwBusy}>
                  <Icon id="ic-lock" />
                  {pwBusy ? 'Changing…' : 'Change password'}
                </button>
              </div>
            </div>
          </div>

          <div className="card usage-card">
            <div className="scard-head">
              <div className="scard-label">Plan usage</div>
              <span className={'pill plan-pill plan-' + plan}>{planLabel}</span>
            </div>
            <div className="usage-grid">
              <UsageBar used={(info?.scans.used) ?? 0} limit={(info?.scans.limit) ?? 0} kind="Scans" hint={Math.max(0, (info?.scans.limit ?? 0) - (info?.scans.used ?? 0)) + ' scans remaining this period'} />
              <UsageBar used={(info?.fixes.used) ?? 0} limit={(info?.fixes.limit) ?? 0} kind="Fixes" hint={Math.max(0, (info?.fixes.limit ?? 0) - (info?.fixes.used ?? 0)) + ' fixes remaining'} />
            </div>
            <div className="pl-note">{planHint}</div>
            <div className="usage-cta">
              <button className="btn" onClick={() => navigate('/pricing')}>Compare plans</button>
              <button className="btn btn-primary" onClick={() => navigate('/pricing')}>View plans / Upgrade</button>
            </div>
          </div>
        </>
      )}
    </section>
  );
}