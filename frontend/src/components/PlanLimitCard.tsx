import { Icon } from '@/components/Icons';
import type { PlanLimitPayload } from '@/types';

interface Props {
  limit: PlanLimitPayload;
  label?: string;
  upgradeTo?: string;
}

/** Upsell card shown when a scan or fix hits the current plan's usage cap. */
export default function PlanLimitCard({ limit, label }: Props) {
  const used = limit.used ?? 0;
  const cap = limit.limit ?? 0;
  const pct = cap > 0 ? Math.min(100, Math.round((used / cap) * 100)) : 0;
  const noun = limit.kind === 'scan' ? 'scans' : 'fixes';
  return (
    <div className="card planlimit" role="status">
      <div className="pl-head">
        <span className="pill ai"><Icon id="ic-verify" />Plan limit</span>
        <span className="pl-plan">{limit.plan || 'free'} plan</span>
      </div>
      <div className="pl-title">You've used your {noun} for this plan.</div>
      <div className="pl-sub">Upgrade to keep scanning with RAMPART.</div>
      <div className="pl-bar-wrap">
        <div className="pl-bar"><span className="pl-fill" style={{ width: pct + '%' }}></span></div>
        <span className="pl-count">{used} / {cap} {noun} used</span>
      </div>
      <a className="btn btn-primary" href="#/pricing">{label || 'View plans / Upgrade'}</a>
    </div>
  );
}