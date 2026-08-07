// Shared scan-progress heuristic (ported from the legacy app.js): the bar never
// completes until the response arrives, and stages are pure functions of elapsed ms.
export interface StageMeta {
  name: string;
  doneNote: string;
  caption: string;
  caps: (string | null)[];
}

export const STAGE_META: StageMeta[] = [
  { name: 'Scan', doneNote: 'Candidates flagged', caption: 'Scanning…',
    caps: ['walking the target tree…', 'parsing files…', 'normalizing findings…'] },
  { name: 'Ground', doneNote: 'Exemplars matched · CWE-filtered', caption: 'Grounding…',
    caps: ['extracting code slices (containing function)…', 'embedding slices · MiniLM…', 'querying hackerone + nuclei collections…'] },
  { name: 'Verify', doneNote: 'Verdicts ranked', caption: 'Verifying…',
    caps: [null, 'grounding verdicts against exemplars…', 'ranking by verdict · severity · confidence…'] },
];

export const STAGE_T1 = 15000;
export const STAGE_T2 = 45000;

/** Piecewise ramp capped at 95% - the bar never completes before the response arrives. */
export function scanProgressPct(el: number): number {
  let p: number;
  if (el < STAGE_T1) p = (el / STAGE_T1) * 30;
  else if (el < STAGE_T2) p = 30 + ((el - STAGE_T1) / (STAGE_T2 - STAGE_T1)) * 40;
  else p = 70 + ((el - STAGE_T2) / 45000) * 25;
  return Math.min(95, p);
}

export type StageState = 'pending' | 'active' | 'done';

export interface StageRow {
  name: string;
  state: StageState;
  note: string;
  time?: string;
}

export function buildStageRows(
  stage: number,
  capIdx: number,
  model: string | null,
  activeScanner: string | undefined,
  stageTimes: (number | null)[],
  completed: boolean,
): StageRow[] {
  return STAGE_META.map((m, i) => {
    const done = stage > i || completed;
    const active = stage === i && !completed;
    let note = '';
    if (done) note = m.doneNote;
    else if (active) {
      const caps = m.caps.map((c) => (c === null ? `one batched call · ${model || 'LLM'}…` : c));
      if (i === 0 && activeScanner) caps[0] = `${activeScanner} · walking the target tree…`;
      note = caps[capIdx % caps.length];
    }
    const dur = stageTimes[i] != null ? stageTimes[i]! - (i ? stageTimes[i - 1] || 0 : 0) : null;
    const time = done && dur != null ? (dur / 1000).toFixed(1) + 's' : '';
    return { name: m.name, state: done ? 'done' as StageState : active ? 'active' as StageState : 'pending' as StageState, note, time };
  });
}