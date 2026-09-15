// Joern CPG provenance helpers: one place that turns /api/health's scanners.joern and a
// report's `joern` block into the words the UI shows. Joern LOCATES logic bugs (IDOR, mass
// assignment, unchecked quantity, TOCTOU); the LLM verdict PROVES them - so the UI never
// calls a Joern candidate "confirmed" on its own.
import type { Finding, Health, JoernInfo } from '@/types';

export const INSTALL_CMD = 'python -m app.services.joern.runtime --install';

export type JoernState = 'ready' | 'starting' | 'script' | 'off' | 'missing' | 'unknown';

export interface JoernStatus {
  state: JoernState;
  label: string;      // short, for a pill:      "CPG ready"
  detail: string;     // one sentence, for a note
  warn: boolean;      // amber dot instead of green
}

/** What the Setup page says about the CPG phase BEFORE the user starts a scan. */
export function joernStatus(health: Health | null | undefined): JoernStatus {
  const j = health?.scanners?.joern;
  if (!health || !j) return { state: 'unknown', label: 'CPG', detail: '', warn: false };
  const enabled = (j.enabled || 'auto').toLowerCase();
  if (['off', 'false', '0', 'no'].includes(enabled)) {
    return { state: 'off', label: 'CPG off', detail: 'Joern CPG phase is disabled (JOERN_ENABLED=off).', warn: true };
  }
  if (!j.available) {
    return {
      state: 'missing', label: 'CPG not installed', warn: true,
      detail: `Joern is not installed, so logic bugs (IDOR, mass assignment, race conditions) are not located. Run: ${INSTALL_CMD}`,
    };
  }
  const s = j.server;
  if (s && s.running && s.ready) {
    return { state: 'ready', label: 'CPG ready', warn: false,
      detail: 'Joern CPG phase is ready (server mode) · IDOR, mass assignment, unchecked quantity, TOCTOU.' };
  }
  if (s && s.running && !s.ready) {
    return { state: 'starting', label: 'CPG starting', warn: true,
      detail: 'Joern CPG server is starting; a scan started now runs the CPG phase in script mode (slower, same results).' };
  }
  return { state: 'script', label: 'CPG script mode', warn: false,
    detail: 'Joern CPG phase runs per scan in script mode (~20-35 s extra) · IDOR, mass assignment, unchecked quantity, TOCTOU.' };
}

/** Will a scan started now run the CPG phase? Only these states do: `available` alone is not
 *  enough (JOERN_ENABLED=off still reports the install as available). */
export function cpgPhaseRuns(health: Health | null | undefined): boolean {
  return ['ready', 'starting', 'script'].includes(joernStatus(health).state);
}

export const isCpg = (f: Finding): boolean => f.tool === 'joern';

/** "pack flask-sqlite3 · fired on id_param_suffix=_id, orm_read_calls=fetchone" - for the badge tooltip. */
export function cpgProvenance(f: Finding): string {
  const m = f.meta || {};
  const parts: string[] = [];
  if (m.pack) parts.push('vocabulary pack ' + m.pack.split('@')[0]);
  if (m.slots) parts.push('fired on ' + m.slots.split(';').filter(Boolean).join(', '));
  if (m.route === 'yes') parts.push('reachable from a route');
  else if (m.route === 'no') parts.push('no route reaches this function (reported, not filtered)');
  return parts.join(' · ');
}

/** Human-readable name of the locator rule, for the CPG badge tooltip. */
export function cpgRuleName(ruleId?: string): string {
  const r = String(ruleId || '');
  if (r.includes('idor')) return 'IDOR - object read without an ownership check';
  if (r.includes('mass-assignment')) return 'Mass assignment - request fields written without an allow-list';
  if (r.includes('quantity')) return 'Unchecked quantity - business value used without a bounds check';
  if (r.includes('toctou')) return 'TOCTOU - check and write not atomic';
  return 'Joern CPG locator';
}

export interface CpgSummary {
  used: boolean;
  candidates: number;       // Joern findings present in the report
  confirmed: number;        // of those, verdict Confirmed
  likely: number;
  cleared: number;          // Informational / False positive - the LLM cleared them
  mode: string;
  elapsedS: string;
  reason: string;           // why the phase did not run (when !used)
  broken: string[];         // rules whose state is not "ok"
  pack: string;             // pack id the rules read ('' when unknown)
  packNote: string;         // "" | "requested pack X rejected, used _base" | "unlisted pack"
}

/** The numbers the summary callout shows: "N of these came from Joern CPG analysis, M confirmed". */
export function cpgSummary(joern: JoernInfo | undefined, findings: Finding[]): CpgSummary {
  const cpg = findings.filter(isCpg);
  const v = (f: Finding) => (f.verdict && f.verdict.verdict) || 'Unverified';
  const rs = joern?.rule_state || {};
  return {
    used: !!joern?.used,
    candidates: cpg.length,
    confirmed: cpg.filter((f) => v(f) === 'Confirmed').length,
    likely: cpg.filter((f) => v(f) === 'Likely').length,
    cleared: cpg.filter((f) => ['Informational', 'False positive'].includes(v(f))).length,
    mode: joern?.mode || '',
    elapsedS: joern?.elapsed_ms != null ? (joern.elapsed_ms / 1000).toFixed(1) : '',
    reason: joern?.reason || joern?.error || '',
    broken: Object.keys(rs).filter((k) => rs[k] && rs[k].state !== 'ok').map((k) => k.replace(/^joern-/, '')),
    pack: joern?.pack?.id || '',
    packNote: joern?.pack?.fallback
      ? `requested pack ${joern.pack.resolved || joern.pack.requested} was rejected, used _base`
      : joern?.pack?.unlisted ? 'unlisted (authoring) pack' : '',
  };
}
