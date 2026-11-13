'use client';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { ReactNode, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { api, useApi, usePersisted } from '@/lib/api';
import type { InvSummary } from '@/lib/types';
import { Icon, StatusDot, VerdictBadge } from '@/components/ui/kit';
import { words } from '@/lib/format';

const GLOBAL = [
  { href: '/', label: 'Intelligence Core', icon: 'core', key: 'c' },
  { href: '/new', label: 'New Investigation', icon: 'plus', key: 'n' },
  { href: '/history', label: 'Investigation History', icon: 'history', key: 'h' },
  { href: '/reports', label: 'Forensic Reports', icon: 'report', key: 'r' },
  { href: '/settings', label: 'Settings & Integrations', icon: 'settings', key: 's' },
];
const CASE = [
  { seg: '', label: 'Investigation Workspace', icon: 'workspace', key: 'w' },
  { seg: '/universe', label: 'Evidence Universe', icon: 'universe', key: 'u' },
  { seg: '/evidence', label: 'Evidence Explorer', icon: 'evidence', key: 'e' },
  { seg: '/timeline', label: 'Temporal Reconstruction', icon: 'timeline', key: 't' },
  { seg: '/lab', label: 'Detection Laboratory', icon: 'lab', key: 'l' },
  { seg: '/dossier', label: 'Forensic Dossier', icon: 'report', key: 'd' },
];

function Wordmark() {
  return (
    <Link href="/" className="flex items-center gap-2.5 px-4" aria-label="ARGUS home">
      <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="12" cy="12" r="10.5" fill="none" stroke="#B9C2CE" strokeOpacity=".5" strokeWidth="1" />
        <ellipse cx="12" cy="12" rx="10.5" ry="4" fill="none" stroke="#B9C2CE" strokeOpacity=".35" strokeWidth="1" transform="rotate(-28 12 12)" />
        <circle cx="12" cy="12" r="3" fill="#FF9D35" />
      </svg>
      <span className="font-display text-[15px] font-semibold tracking-[0.22em] text-paper">ARGUS</span>
    </Link>
  );
}

interface Hit { type: string; investigation_id: string; label: string; sub: string; ref?: string }
interface Cmd { id: string; label: string; sub?: string; icon: string; run: () => void }

function CommandPalette({ open, onClose, caseId }: { open: boolean; onClose: () => void; caseId: string | null }) {
  const router = useRouter();
  const [q, setQ] = useState('');
  const [hits, setHits] = useState<Hit[]>([]);
  const [searching, setSearching] = useState(false);
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => { if (open) { setQ(''); setHits([]); setSel(0); setTimeout(() => input.current?.focus(), 20); } }, [open]);
  useEffect(() => {
    if (q.trim().length < 2) { setHits([]); return; }
    setSearching(true);
    const t = setTimeout(() => {
      api<Hit[]>(`/search?q=${encodeURIComponent(q.trim())}`).then(setHits).catch(() => setHits([])).finally(() => setSearching(false));
    }, 180);
    return () => clearTimeout(t);
  }, [q]);

  const go = useCallback((href: string) => { onClose(); router.push(href); }, [onClose, router]);
  const cmds: Cmd[] = useMemo(() => {
    const nav: Cmd[] = [
      ...(caseId ? CASE.map((c) => ({ id: `case${c.seg}`, label: c.label, sub: `Case ${caseId}`, icon: c.icon, run: () => go(`/i/${caseId}${c.seg}`) })) : []),
      ...GLOBAL.map((g) => ({ id: g.href, label: g.label, sub: 'Navigate', icon: g.icon, run: () => go(g.href) })),
    ].filter((c) => !q || c.label.toLowerCase().includes(q.toLowerCase()));
    const found: Cmd[] = hits.map((h, i) => ({
      id: `hit${i}`, label: h.label, sub: `${h.type} · ${h.sub}`, icon: h.type === 'investigation' ? 'workspace' : h.type === 'evidence' ? 'evidence' : h.type === 'finding' ? 'alert' : 'universe',
      run: () => go(h.type === 'indicator' ? `/i/${h.investigation_id}/universe?focus=${encodeURIComponent(h.ref || '')}` : h.type === 'evidence' ? `/i/${h.investigation_id}/evidence?e=${h.ref}` : h.type === 'finding' ? `/i/${h.investigation_id}?f=${h.ref}` : `/i/${h.investigation_id}`),
    }));
    return [...found, ...nav];
  }, [q, hits, caseId, go]);
  useEffect(() => { setSel(0); }, [q, hits.length]);

  return (
    <AnimatePresence>
      {open && (
        <motion.div className="fixed inset-0 z-50 flex items-start justify-center bg-obsidian/70 pt-[14vh] backdrop-blur-sm" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.12 }} onMouseDown={onClose}>
          <motion.div role="dialog" aria-modal="true" aria-label="Command palette" className="panel-solid w-[min(640px,92vw)] shadow-panel" initial={{ y: -8, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: -8, opacity: 0 }} transition={{ duration: 0.14 }} onMouseDown={(e) => e.stopPropagation()}
            onKeyDown={(e) => {
              if (e.key === 'Escape') onClose();
              if (e.key === 'ArrowDown') { e.preventDefault(); setSel((s) => Math.min(s + 1, cmds.length - 1)); }
              if (e.key === 'ArrowUp') { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
              if (e.key === 'Enter' && cmds[sel]) cmds[sel].run();
            }}>
            <div className="flex h-12 items-center gap-3 border-b border-line px-4">
              <Icon name="search" className="text-titanium-mute" />
              <input ref={input} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search indicators, evidence, findings, investigations — or jump to a view" aria-label="Search" className="h-full flex-1 bg-transparent text-body text-paper placeholder:text-titanium-faint focus:outline-none" />
              {searching && <span className="micro animate-blink">searching</span>}
              <kbd className="micro border border-line px-1.5">esc</kbd>
            </div>
            <ul className="max-h-[52vh] overflow-auto py-1" role="listbox">
              {cmds.length === 0 && <li className="px-4 py-6 text-center text-body text-titanium-mute">No match for “{q}”. Search covers indicator values, evidence names and hashes, finding titles and investigation titles.</li>}
              {cmds.map((c, i) => (
                <li key={c.id} role="option" aria-selected={i === sel}>
                  <button onMouseEnter={() => setSel(i)} onClick={c.run} className={`flex w-full items-center gap-3 px-4 py-2 text-left ${i === sel ? 'bg-elevated' : ''}`}>
                    <Icon name={c.icon} className={i === sel ? 'text-amber' : 'text-titanium-mute'} />
                    <span className="min-w-0 flex-1 truncate text-body text-paper">{c.label}</span>
                    <span className="micro shrink-0 truncate">{c.sub}</span>
                  </button>
                </li>
              ))}
            </ul>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function Shortcuts({ open, onClose, inCase }: { open: boolean; onClose: () => void; inCase: boolean }) {
  if (!open) return null;
  const rows: [string, string][] = [['⌘K  /  Ctrl K', 'Command palette and search'], ['/', 'Search'], ['?', 'This overlay'], ['Esc', 'Close overlays, clear selection'],
    ...GLOBAL.map((g) => [`g ${g.key}`, g.label] as [string, string]), ...(inCase ? CASE.map((c) => [`g ${c.key}`, c.label] as [string, string]) : [])];
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-obsidian/70 backdrop-blur-sm" onMouseDown={onClose}>
      <div role="dialog" aria-modal="true" aria-label="Keyboard shortcuts" className="panel-solid w-[min(520px,92vw)] p-5 shadow-panel" onMouseDown={(e) => e.stopPropagation()}>
        <div className="mb-3 flex items-center justify-between"><h2 className="h-display text-[17px]">Keyboard shortcuts</h2><button className="btn-ghost" onClick={onClose} aria-label="Close"><Icon name="close" /></button></div>
        <dl className="grid grid-cols-[120px_1fr] gap-y-1.5">{rows.map(([k, v]) => (<div key={k} className="contents"><dt className="data text-amber">{k}</dt><dd className="text-body text-titanium">{v}</dd></div>))}</dl>
        {!inCase && <p className="micro mt-4 normal-case tracking-normal">Case views (workspace, universe, timeline…) get their own “g” shortcuts once an investigation is open.</p>}
      </div>
    </div>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const path = usePathname() || '/';
  const router = useRouter();
  const caseId = path.match(/^\/i\/([A-Z]+-[0-9A-F]+)/)?.[1] || null;
  const [lastCase, setLastCase] = usePersisted<string | null>('argus.lastCase', null);
  const activeCase = caseId || lastCase;
  const { data: inv, error: invErr } = useApi<InvSummary>(activeCase ? `/investigations/${activeCase}` : null, 4000);
  const { error: healthErr } = useApi<{ status: string }>('/health', 15000);
  const [palette, setPalette] = useState(false);
  const [help, setHelp] = useState(false);
  const [navOpen, setNavOpen] = useState(false);
  const gPending = useRef(0);

  useEffect(() => { if (caseId) setLastCase(caseId); }, [caseId, setLastCase]);
  useEffect(() => { if (invErr?.status === 404 && !caseId) setLastCase(null); }, [invErr, caseId, setLastCase]);
  useEffect(() => { setNavOpen(false); }, [path]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      const typing = el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable;
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPalette((p) => !p); return; }
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === '/') { e.preventDefault(); setPalette(true); return; }
      if (e.key === '?') { setHelp((h) => !h); return; }
      if (e.key === 'Escape') { setHelp(false); return; }
      if (e.key === 'g') { gPending.current = Date.now(); return; }
      if (Date.now() - gPending.current < 900) {
        gPending.current = 0;
        const g = GLOBAL.find((x) => x.key === e.key);
        if (g) { router.push(g.href); return; }
        const c = CASE.find((x) => x.key === e.key);
        if (c && activeCase) router.push(`/i/${activeCase}${c.seg}`);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [router, activeCase]);

  const item = (href: string, label: string, icon: string, active: boolean) => (
    <Link key={href} href={href} aria-current={active ? 'page' : undefined}
      className={`group relative flex h-9 items-center gap-3 px-4 text-body transition-colors ${active ? 'bg-elevated text-paper' : 'text-titanium-mute hover:text-paper'}`}>
      {active && <span className="absolute inset-y-0 left-0 w-[2px] bg-amber" />}
      <Icon name={icon} className={active ? 'text-amber' : ''} /><span className="truncate">{label}</span>
    </Link>
  );

  const nav = (
    <nav aria-label="Primary" className="flex h-full flex-col">
      <div className="flex h-14 shrink-0 items-center border-b border-line"><Wordmark /></div>
      <div className="flex-1 overflow-auto py-3">
        <div className="micro px-4 pb-1.5">Engine</div>
        {GLOBAL.slice(0, 2).map((g) => item(g.href, g.label, g.icon, path === g.href))}
        <div className="micro mt-5 flex items-center gap-2 px-4 pb-1.5"><span>Active case</span><div className="ticks flex-1 opacity-50" /></div>
        {activeCase && inv ? (
          <>
            <div className="mb-1 px-4 pb-2">
              <div className="truncate font-display text-[13px] text-paper" title={inv.title}>{inv.title}</div>
              <div className="mt-1 flex items-center gap-2"><StatusDot status={inv.status} /><span className="micro">{inv.id}</span></div>
            </div>
            {CASE.map((c) => item(`/i/${activeCase}${c.seg}`, c.label, c.icon, path === `/i/${activeCase}${c.seg}`))}
          </>
        ) : (
          <p className="px-4 text-data text-titanium-faint">No case open. Start a new investigation or open one from history.</p>
        )}
        <div className="micro mt-5 px-4 pb-1.5">Archive</div>
        {GLOBAL.slice(2).map((g) => item(g.href, g.label, g.icon, path === g.href))}
      </div>
      <button onClick={() => setHelp(true)} className="flex h-10 shrink-0 items-center gap-3 border-t border-line px-4 text-titanium-mute hover:text-paper"><Icon name="keyboard" /><span className="micro">Shortcuts</span><kbd className="micro ml-auto border border-line px-1.5">?</kbd></button>
    </nav>
  );

  return (
    <div className="flex h-screen overflow-hidden">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:bg-amber focus:px-3 focus:py-1 focus:text-obsidian">Skip to content</a>
      <aside className="no-print hidden w-[248px] shrink-0 border-r border-line bg-graphite/60 lg:block">{nav}</aside>
      <AnimatePresence>
        {navOpen && (
          <motion.div className="no-print fixed inset-0 z-40 bg-obsidian/70 lg:hidden" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setNavOpen(false)}>
            <motion.aside className="h-full w-[264px] border-r border-line bg-graphite" initial={{ x: -264 }} animate={{ x: 0 }} exit={{ x: -264 }} transition={{ type: 'tween', duration: 0.18 }} onClick={(e) => e.stopPropagation()}>{nav}</motion.aside>
          </motion.div>
        )}
      </AnimatePresence>
      <div className="print-root flex min-w-0 flex-1 flex-col">
        <header className="no-print flex h-14 shrink-0 items-center gap-3 border-b border-line bg-obsidian/80 px-3 backdrop-blur-md sm:px-4">
          <button className="btn-ghost px-2 lg:hidden" onClick={() => setNavOpen(true)} aria-label="Open navigation"><Icon name="layers" /></button>
          <div className="min-w-0 flex-1">
            {caseId && inv ? (
              <div className="flex min-w-0 items-center gap-3">
                <span className="data hidden shrink-0 text-titanium-mute sm:inline">{inv.id}</span>
                <span className="truncate font-display text-[14px] text-paper">{inv.title}</span>
                <span className="hidden shrink-0 items-center gap-1.5 md:inline-flex"><StatusDot status={inv.status} /><span className="micro">{inv.status === 'running' ? words(inv.stage) : inv.status}</span></span>
                {inv.verdict && <span className="hidden shrink-0 md:inline"><VerdictBadge verdict={inv.verdict} confidence={inv.verdict_confidence} /></span>}
              </div>
            ) : (
              <>
                <span className="font-display text-[14px] font-semibold tracking-[0.22em] text-paper lg:hidden">ARGUS</span>
                <span className="micro hidden truncate lg:block">Autonomous digital investigation &amp; threat intelligence engine</span>
              </>
            )}
          </div>
          <button onClick={() => setPalette(true)} className="flex h-8 items-center gap-2 border border-line-strong px-2.5 text-titanium-mute hover:border-titanium hover:text-paper" aria-label="Open search and command palette">
            <Icon name="search" size={14} /><span className="hidden text-data sm:inline">Search</span><kbd className="micro hidden border border-line px-1 sm:inline">⌘K</kbd>
          </button>
          <div className="flex items-center gap-1.5" title={healthErr ? healthErr.message : 'Backend connected'}>
            <span className={`h-1.5 w-1.5 ${healthErr ? 'bg-threat animate-blink' : 'bg-cyan'}`} /><span className="micro hidden sm:inline">{healthErr ? 'engine offline' : 'engine online'}</span>
          </div>
        </header>
        <main id="main" className="print-root relative min-h-0 flex-1 overflow-auto">{children}</main>
      </div>
      <CommandPalette open={palette} onClose={() => setPalette(false)} caseId={activeCase} />
      <Shortcuts open={help} onClose={() => setHelp(false)} inCase={!!activeCase} />
    </div>
  );
}
