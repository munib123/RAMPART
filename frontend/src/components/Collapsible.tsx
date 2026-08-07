import { useState, type ReactNode } from 'react';
import { Icon } from '@/components/Icons';

export default function Collapsible({ label, defaultOpen = false, children, className }: {
  label: string;
  defaultOpen?: boolean;
  children: ReactNode;
  className?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={'coll ' + (className || '') + (open ? ' is-open' : '')}>
      <button className="coll-toggle" aria-expanded={open} onClick={() => setOpen(!open)}>
        <Icon id="ic-chevron" /> {label}
      </button>
      <div className="coll-body">{children}</div>
    </div>
  );
}