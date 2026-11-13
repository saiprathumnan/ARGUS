'use client';
import { ReactNode } from 'react';
import type { Severity } from '@/lib/types';
import { sevBorder, sevText, VERDICT, words } from '@/lib/format';
import { ApiError } from '@/lib/api';

const P: Record<string, string> = {
  core: 'M12 3a9 9 0 100 18 9 9 0 000-18zm0 5a4 4 0 110 8 4 4 0 010-8z',
  plus: 'M12 5v14M5 12h14',
  workspace: 'M4 5h16v14H4zM4 10h16M10 10v9',
  universe: 'M12 12m-2 0a2 2 0 104 0 2 2 0 10-4 0M5 6m-1.5 0a1.5 1.5 0 103 0 1.5 1.5 0 10-3 0M19 7m-1.5 0a1.5 1.5 0 103 0 1.5 1.5 0 10-3 0M7 19m-1.5 0a1.5 1.5 0 103 0 1.5 1.5 0 10-3 0M6.2 7.1l4.3 3.6M17.7 8l-4.1 2.9M8 17.8l2.9-4.2',
  evidence: 'M6 3h9l4 4v14H6zM15 3v4h4M9 12h7M9 16h7',
  timeline: 'M3 12h18M7 8v8M12 6v12M17 9v6',
  lab: 'M9 3h6M10 3v6l-5 10a1 1 0 001 1.5h12a1 1 0 001-1.5L14 9V3M7.5 15h9',
  history: 'M12 7v5l3 2M4 12a8 8 0 108-8 8 8 0 00-6.3 3M4 4v4h4',
  report: 'M6 3h12v18H6zM9 8h6M9 12h6M9 16h3',
  settings: 'M4 7h10M18 7h2M4 17h2M10 17h10M14 5v4M6 15v4',
  search: 'M11 11m-6 0a6 6 0 1012 0 6 6 0 10-12 0M16 16l4 4',
  close: 'M6 6l12 12M18 6L6 18',
  check: 'M5 12l5 5 9-10',
  alert: 'M12 4l9 16H3zM12 10v5M12 17.5v.5',
  arrow: 'M5 12h14M13 6l6 6-6 6',
  play: 'M7 5l12 7-12 7z',
  pause: 'M8 5v14M16 5v14',
  upload: 'M12 16V4M7 9l5-5 5 5M5 20h14',
  link: 'M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1',
  trash: 'M5 7h14M9 7V4h6v3M7 7l1 13h8l1-13',
  print: 'M7 8V3h10v5M7 17H4V8h16v9h-3M7 14h10v7H7z',
  focus: 'M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5',
  layers: 'M12 3l9 5-9 5-9-5zM3 12l9 5 9-5M3 16l9 5 9-5',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
  keyboard: 'M3 7h18v10H3zM7 11h.01M11 11h.01M15 11h.01M8 14h8',
};

export function Icon({ name, size = 16, className = '' }: { name: keyof typeof P | string; size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d={P[name] || P.core} />
    </svg>
  );
}

/** Panel with the instrument header: micro label, calibration ticks, optional actions. */
export function Panel({ title, meta, actions, children, className = '', bodyClass = '' }: { title?: string; meta?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClass?: string }) {
  return (
    <section className={`panel flex min-h-0 flex-col ${className}`}>
      {title && (
        <header className="flex h-9 shrink-0 items-center gap-3 border-b border-line px-3">
          <h2 className="micro min-w-0 truncate whitespace-nowrap text-titanium">{title}</h2>
          <div className="ticks min-w-0 flex-1 opacity-60" />
          {meta && <div className="micro shrink-0 whitespace-nowrap">{meta}</div>}
          {actions}
        </header>
      )}
      <div className={`min-h-0 flex-1 ${bodyClass}`}>{children}</div>
    </section>
  );
}

export function SeverityTag({ severity }: { severity: Severity }) {
  return <span className={`inline-block border-l-2 pl-1.5 font-mono text-micro uppercase ${sevBorder[severity]} ${sevText[severity]}`}>{severity}</span>;
}

export function Tag({ children, tone = 'default' }: { children: ReactNode; tone?: 'default' | 'amber' | 'cyan' | 'threat' }) {
  const t = { default: 'border-line-strong text-titanium-mute', amber: 'border-amber/50 text-amber', cyan: 'border-cyan/50 text-cyan', threat: 'border-threat/50 text-threat' }[tone];
  return <span className={`inline-flex h-[18px] items-center border px-1.5 font-mono text-micro uppercase ${t}`}>{children}</span>;
}

export function VerdictBadge({ verdict, confidence, large }: { verdict: string | null; confidence?: number | null; large?: boolean }) {
  if (!verdict) return <Tag>not assessed</Tag>;
  const v = VERDICT[verdict] || VERDICT.insufficient_evidence;
  return (
    <span className={`inline-flex items-center gap-2 border ${v.tone} ${large ? 'h-9 px-3 font-display text-[15px]' : 'h-[22px] px-2 font-mono text-micro uppercase'}`}>
      {v.label}{confidence != null && <span className="opacity-70">· {Math.round(confidence * 100)}%</span>}
    </span>
  );
}

export function StatusDot({ status }: { status: string }) {
  const c = { running: 'bg-amber animate-blink', completed: 'bg-cyan', failed: 'bg-threat', created: 'bg-titanium-faint', skipped: 'bg-titanium-faint', pending: 'bg-titanium-faint' }[status] || 'bg-titanium-faint';
  return <span className={`inline-block h-1.5 w-1.5 shrink-0 ${c}`} aria-label={status} />;
}

export function Classification({ value }: { value: string }) {
  const tone = value === 'confirmed_malicious' ? 'threat' : value === 'suspicious' ? 'amber' : value === 'benign' ? 'cyan' : 'default';
  return <Tag tone={tone as any}>{words(value)}</Tag>;
}

export function Empty({ icon = 'core', title, children, action }: { icon?: string; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex h-full min-h-[160px] flex-col items-center justify-center gap-3 p-8 text-center">
      <Icon name={icon} size={22} className="text-titanium-faint" />
      <div className="font-display text-[15px] text-paper">{title}</div>
      {children && <p className="max-w-md text-body text-titanium-mute">{children}</p>}
      {action}
    </div>
  );
}

export function ErrorState({ error, retry }: { error: ApiError | Error; retry?: () => void }) {
  const status = (error as ApiError).status;
  return (
    <div className="flex h-full min-h-[160px] flex-col items-center justify-center gap-3 p-8 text-center" role="alert">
      <Icon name="alert" size={22} className="text-threat" />
      <div className="font-display text-[15px] text-paper">{status === 404 ? 'Not found' : status === 502 || status === 0 ? 'Backend unreachable' : 'Request failed'}</div>
      <p className="max-w-md text-body text-titanium-mute">{error.message}</p>
      {retry && <button className="btn" onClick={retry}>Retry</button>}
    </div>
  );
}

export function Loading({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex h-full min-h-[120px] flex-col items-center justify-center gap-3" role="status" aria-live="polite">
      <div className="relative h-px w-40 overflow-hidden bg-line"><div className="absolute inset-y-0 w-1/4 animate-sweep bg-amber" /></div>
      <div className="micro">{label}</div>
    </div>
  );
}

export function KV({ k, children, mono = true }: { k: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[112px_1fr] gap-3 border-b border-line py-1.5 last:border-0">
      <dt className="micro pt-0.5">{k}</dt>
      <dd className={`min-w-0 break-words ${mono ? 'data' : 'text-body text-titanium'}`}>{children}</dd>
    </div>
  );
}

export function Meter({ value, tone = 'amber' }: { value: number; tone?: 'amber' | 'cyan' | 'threat' }) {
  const c = { amber: 'bg-amber', cyan: 'bg-cyan', threat: 'bg-threat' }[tone];
  return <div className="h-[3px] w-full bg-line" role="meter" aria-valuenow={Math.round(value * 100)} aria-valuemin={0} aria-valuemax={100}><div className={`h-full ${c}`} style={{ width: `${Math.max(0, Math.min(1, value)) * 100}%` }} /></div>;
}

export function Segmented<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: { id: T; label: string }[]; label: string }) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex border border-line-strong">
      {options.map((o) => (
        <button key={o.id} role="radio" aria-checked={value === o.id} onClick={() => onChange(o.id)}
          className={`h-7 px-2.5 font-mono text-micro uppercase transition-colors ${value === o.id ? 'bg-titanium text-obsidian' : 'text-titanium-mute hover:text-paper'}`}>{o.label}</button>
      ))}
    </div>
  );
}

export function Chip({ active, onClick, children, color }: { active: boolean; onClick: () => void; children: ReactNode; color?: string }) {
  return (
    <button onClick={onClick} aria-pressed={active}
      className={`inline-flex h-6 items-center gap-1.5 border px-2 font-mono text-micro uppercase transition-colors ${active ? 'border-line-strong text-paper' : 'border-line text-titanium-faint line-through decoration-titanium-faint'}`}>
      {color && <span className="h-1.5 w-1.5" style={{ background: active ? color : '#4A5360' }} />}{children}
    </button>
  );
}
