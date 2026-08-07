// Line-level diff sharing the LCS algorithm from the legacy app.js.
import type { ReactNode } from 'react';
import type { DiffLine } from '@/types';

export function diffLines(a: string, b: string): DiffLine[] {
  const A = (a || '').split('\n');
  const B = (b || '').split('\n');
  const m = A.length, n = B.length;
  const dp = Array.from({ length: m + 1 }, () => new Int32Array(n + 1));
  for (let i = m - 1; i >= 0; i--)
    for (let j = n - 1; j >= 0; j--)
      dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out: DiffLine[] = []; let i = 0, j = 0;
  while (i < m && j < n) {
    if (A[i] === B[j]) { out.push({ t: 'ctx', s: A[i] }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push({ t: 'del', s: A[i] }); i++; }
    else { out.push({ t: 'add', s: B[j] }); j++; }
  }
  while (i < m) out.push({ t: 'del', s: A[i++] });
  while (j < n) out.push({ t: 'add', s: B[j++] });
  return out;
}

export function diffReact(diff: DiffLine[]): ReactNode {
  return (
    <pre className="diff" aria-label="unified diff of the suggested fix">
      {diff.map((d, idx) => {
        const cls = d.t === 'add' ? 'dl-add' : d.t === 'del' ? 'dl-del' : 'dl-ctx';
        const g = d.t === 'add' ? '+' : d.t === 'del' ? '−' : ' ';
        const sr = d.t === 'add' ? <span className="sr-only">Added: </span> : d.t === 'del' ? <span className="sr-only">Removed: </span> : null;
        return (
          <span className={`dl ${cls}`} key={idx}>
            <span className="dg" aria-hidden="true">{g}</span>
            {sr}
            {d.s || ' '}
          </span>
        );
      })}
    </pre>
  );
}