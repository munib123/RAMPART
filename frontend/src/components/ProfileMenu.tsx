import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import type { User } from '@/types';
import { Icon } from '@/components/Icons';

export function initialsOf(user: User): string {
  const raw = (user.name || user.email || '?').trim();
  if (!raw) return '?';
  const parts = raw.split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return raw.slice(0, 2).toUpperCase();
}

export default function ProfileMenu({ user, onSignOut }: { user: User; onSignOut: () => void }) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const display = (user.name || '').trim() || user.email.split('@')[0] || user.email;

  return (
    <div className="profile" ref={wrapRef}>
      <button
        type="button"
        className="profile-trigger"
        aria-haspopup="menu"
        aria-expanded={open}
        title="Account menu"
        onClick={() => setOpen((o) => !o)}
      >
        <span className="profile-avatar" aria-hidden="true">{initialsOf(user)}</span>
        <span className="profile-name">{display}</span>
        <Icon id="ic-chevron" svgClass={'profile-caret' + (open ? ' is-open' : '')} />
      </button>
      {open && (
        <div className="profile-menu" role="menu" aria-label="Account">
          <div className="profile-head">
            <span className="profile-avatar lg" aria-hidden="true">{initialsOf(user)}</span>
            <div className="profile-head-meta">
              <span className="profile-head-name">{display}</span>
              <span className="profile-head-mail">{user.email}</span>
            </div>
          </div>
          <button type="button" className="profile-item" role="menuitem" onClick={() => { setOpen(false); navigate('/profile'); }}>
            <svg className="profile-item-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <circle cx="12" cy="8" r="4" />
              <path d="M4 21a8 8 0 0 1 16 0" />
            </svg>
            Profile
          </button>
          <button type="button" className="profile-item" role="menuitem" onClick={() => { setOpen(false); navigate('/history'); }}>
            <svg className="profile-item-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <circle cx="12" cy="12" r="9" />
              <path d="M12 7v5l3 2" />
            </svg>
            History
          </button>
          <button type="button" className="profile-item" role="menuitem" onClick={() => { setOpen(false); navigate('/pricing'); }}>
            <svg className="profile-item-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <rect x="3" y="6" width="18" height="13" rx="2" />
              <path d="M3 10h18" />
            </svg>
            Plans & pricing
          </button>
          <div className="profile-sep" role="separator"></div>
          <button type="button" className="profile-item" role="menuitem" onClick={() => { setOpen(false); onSignOut(); }}>Sign out</button>
        </div>
      )}
    </div>
  );
}