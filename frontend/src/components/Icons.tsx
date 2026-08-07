import { type ReactNode } from 'react';

export const svg = (id: string, cls?: string): ReactNode => <svg className={cls}><use href={`#${id}`} /></svg>;

export function Icon({ id, svgClass }: { id: string; svgClass?: string }) {
  return (
    <svg className={svgClass} aria-hidden="true">
      <use href={`#${id}`} />
    </svg>
  );
}