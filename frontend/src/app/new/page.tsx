'use client';
import { useRouter } from 'next/navigation';
import { useCallback, useRef, useState } from 'react';
import { api, ApiError, useApi } from '@/lib/api';
import type { InvSummary, SystemInfo } from '@/lib/types';
import { Icon, Panel, Tag } from '@/components/ui/kit';
import { bytes, KIND_LABEL } from '@/lib/format';

type Staged =
  | { key: string; type: 'file'; file: File; kind: string; sourceUrl: string; state: 'staged' | 'ok' | 'error'; error?: string }
  | { key: string; type: 'url'; url: string; state: 'staged' | 'ok' | 'error'; error?: string }
  | { key: string; type: 'text'; kind: 'email_headers' | 'json_events' | 'auth_log'; content: string; name: string; state: 'staged' | 'ok' | 'error'; error?: string };

const FILE_KINDS = ['auto', 'eml', 'email_headers', 'json_events', 'auth_log', 'pcap', 'pdf', 'screenshot', 'file'];
let seq = 0;

export default function NewInvestigation() {
  const router = useRouter();
  const sys = useApi<SystemInfo>('/system');
  const [title, setTitle] = useState('');
  const [desc, setDesc] = useState('');
  const [items, setItems] = useState<Staged[]>([]);
  const [url, setUrl] = useState('');
  const [text, setText] = useState('');
  const [textKind, setTextKind] = useState<'email_headers' | 'json_events' | 'auth_log'>('email_headers');
  const [drag, setDrag] = useState(false);
  const [phase, setPhase] = useState<'edit' | 'submitting'>('edit');
  const [progress, setProgress] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [createdId, setCreatedId] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const maxBytes = sys.data?.limits.max_upload_bytes ?? 25 * 1024 * 1024;

  const addFiles = useCallback((files: FileList | File[]) => {
    const next: Staged[] = [];
    for (const f of Array.from(files)) {
      next.push({ key: `f${seq++}`, type: 'file', file: f, kind: 'auto', sourceUrl: '', state: f.size > maxBytes ? 'error' : 'staged', error: f.size > maxBytes ? `Exceeds the ${bytes(maxBytes)} upload limit` : f.size === 0 ? 'File is empty' : undefined });
    }
    setItems((p) => [...p, ...next]);
  }, [maxBytes]);
  const addUrl = () => {
    const u = url.trim();
    if (!u) return;
    if (/\s/.test(u) || u.length > 2048) { setError('A URL cannot contain spaces and must be under 2048 characters.'); return; }
    setItems((p) => [...p, { key: `u${seq++}`, type: 'url', url: u, state: 'staged' }]); setUrl(''); setError(null);
  };
  const addText = () => {
    if (!text.trim()) return;
    setItems((p) => [...p, { key: `t${seq++}`, type: 'text', kind: textKind, content: text, name: `pasted-${textKind}.txt`, state: 'staged' }]); setText('');
  };
  const patch = (key: string, p: Partial<Staged>) => setItems((prev) => prev.map((i) => (i.key === key ? ({ ...i, ...p } as Staged) : i)));
  const usable = items.filter((i) => i.state !== 'error' || createdId);
  const canSubmit = title.trim().length > 0 && items.some((i) => i.state === 'staged' && !i.error) && phase === 'edit';

  const submit = async () => {
    setPhase('submitting'); setError(null);
    let id = createdId;
    try {
      if (!id) {
        setProgress('Creating investigation');
        id = (await api<InvSummary>('/investigations', { method: 'POST', body: JSON.stringify({ title: title.trim(), description: desc.trim() }) })).id;
        setCreatedId(id);
      }
      let ok = items.filter((i) => i.state === 'ok').length, failed = 0;
      for (const it of items) {
        if (it.state !== 'staged' || it.error) continue;
        setProgress(`Submitting ${it.type === 'file' ? it.file.name : it.type === 'url' ? it.url : it.name}`);
        try {
          if (it.type === 'url') await api(`/investigations/${id}/evidence/url`, { method: 'POST', body: JSON.stringify({ url: it.url }) });
          else if (it.type === 'text') await api(`/investigations/${id}/evidence/text`, { method: 'POST', body: JSON.stringify({ kind: it.kind, content: it.content, name: it.name }) });
          else {
            const fd = new FormData(); fd.append('file', it.file); fd.append('kind', it.kind);
            if (it.sourceUrl.trim()) fd.append('source_url', it.sourceUrl.trim());
            await api(`/investigations/${id}/evidence/file`, { method: 'POST', body: fd });
          }
          patch(it.key, { state: 'ok', error: undefined }); ok++;
        } catch (e) { patch(it.key, { state: 'error', error: (e as ApiError).message }); failed++; }
      }
      if (ok === 0) { setError('No evidence was accepted, so analysis was not started. Fix or remove the rejected items and submit again.'); setPhase('edit'); return; }
      if (failed > 0) { setError(`${failed} item(s) were rejected and ${ok} accepted. Remove or fix the rejected items, or start analysis with the accepted evidence.`); setPhase('edit'); return; }
      setProgress('Starting analysis');
      await api(`/investigations/${id}/start`, { method: 'POST' });
      router.push(`/i/${id}`);
    } catch (e) { setError((e as ApiError).message); setPhase('edit'); }
  };
  const startAccepted = async () => {
    if (!createdId) return;
    setPhase('submitting'); setProgress('Starting analysis');
    try { await api(`/investigations/${createdId}/start`, { method: 'POST' }); router.push(`/i/${createdId}`); } catch (e) { setError((e as ApiError).message); setPhase('edit'); }
  };

  return (
    <div className="mx-auto max-w-[1100px] px-5 py-8 lg:px-10">
      <div className="micro text-amber">New investigation</div>
      <h1 className="h-display mt-2 text-[30px]">Open a case and submit evidence</h1>
      <p className="mt-2 max-w-[70ch] text-body text-titanium">Evidence is hashed on arrival, stored unmodified and never executed. Analysis starts when you launch the case and runs on the backend.</p>

      <div className="mt-7 grid gap-4 lg:grid-cols-[minmax(0,5fr)_minmax(0,4fr)]">
        <div className="space-y-4">
          <Panel title="01 · Case">
            <div className="space-y-3 p-3">
              <label className="block"><span className="micro">Title</span><input className="field mt-1" value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Invoice phishing reported by finance, 3 Nov" disabled={!!createdId} /></label>
              <label className="block"><span className="micro">Notes (optional)</span><textarea className="field mt-1 h-20 py-2" value={desc} maxLength={4000} onChange={(e) => setDesc(e.target.value)} placeholder="Who reported it, what you already know, what you want answered." disabled={!!createdId} /></label>
            </div>
          </Panel>
          <Panel title="02 · Evidence">
            <div className="space-y-4 p-3">
              <div onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)} onDrop={(e) => { e.preventDefault(); setDrag(false); addFiles(e.dataTransfer.files); }}
                className={`flex flex-col items-center gap-2 border border-dashed px-4 py-7 text-center transition-colors ${drag ? 'border-amber bg-amber-dim' : 'border-line-strong'}`}>
                <Icon name="upload" size={20} className="text-titanium-mute" />
                <div className="text-body text-paper">Drop files here, or <button className="text-cyan underline-offset-2 hover:underline" onClick={() => fileInput.current?.click()}>browse</button></div>
                <div className="micro normal-case tracking-normal">.eml · email headers · .pcap / .pcapng · JSON event logs · auth.log · PDF · screenshots · any file for static analysis — up to {bytes(maxBytes)} each</div>
                <input ref={fileInput} type="file" multiple className="sr-only" aria-label="Choose evidence files" onChange={(e) => { if (e.target.files) addFiles(e.target.files); e.target.value = ''; }} />
              </div>
              <div>
                <span className="micro">Suspicious URL</span>
                <div className="mt-1 flex gap-2"><input className="field font-mono text-data" value={url} onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addUrl()} placeholder="http://example.test/login" aria-label="Suspicious URL" /><button className="btn h-9 shrink-0" onClick={addUrl} disabled={!url.trim()}>Add URL</button></div>
                <p className="micro mt-1 normal-case tracking-normal">{sys.data?.network.live_url_fetch ? 'Live fetching is enabled: ARGUS will request the URL through its SSRF guard.' : 'Live fetching is disabled: the URL is analysed as text and never requested.'}</p>
              </div>
              <div>
                <div className="flex items-center justify-between"><span className="micro">Paste text</span>
                  <select className="field h-7 w-auto py-0 font-mono text-micro uppercase" value={textKind} onChange={(e) => setTextKind(e.target.value as any)} aria-label="Pasted text type"><option value="email_headers">Email headers</option><option value="json_events">JSON events</option><option value="auth_log">Linux auth log</option></select></div>
                <textarea className="field mt-1 h-24 py-2 font-mono text-data" value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste raw headers, JSON / NDJSON events, or auth.log lines" aria-label="Pasted evidence text" />
                <button className="btn mt-2" onClick={addText} disabled={!text.trim()}>Add pasted text</button>
              </div>
            </div>
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel title="03 · Review and launch" meta={`${usable.length} item${usable.length === 1 ? '' : 's'}`}>
            {items.length === 0 ? (
              <div className="p-6 text-center text-body text-titanium-mute">Nothing staged yet. Add at least one piece of evidence to launch.</div>
            ) : (
              <ul>
                {items.map((it) => (
                  <li key={it.key} className="border-b border-line px-3 py-2">
                    <div className="flex items-center gap-2">
                      <Icon name={it.type === 'url' ? 'link' : 'evidence'} size={14} className={it.state === 'error' || it.error ? 'text-threat' : it.state === 'ok' ? 'text-cyan' : 'text-titanium-mute'} />
                      <span className="data min-w-0 flex-1 truncate text-paper">{it.type === 'file' ? it.file.name : it.type === 'url' ? it.url : `${KIND_LABEL[it.kind]} (pasted, ${bytes(it.content.length)})`}</span>
                      {it.type === 'file' && <span className="micro shrink-0">{bytes(it.file.size)}</span>}
                      {it.state === 'ok' ? <Tag tone="cyan">accepted</Tag> : phase === 'edit' && <button className="btn-ghost h-6 px-1" aria-label="Remove" onClick={() => setItems((p) => p.filter((x) => x.key !== it.key))}><Icon name="close" size={13} /></button>}
                    </div>
                    {it.type === 'file' && it.state === 'staged' && !it.error && (
                      <div className="mt-1.5 flex flex-wrap items-center gap-2 pl-6">
                        <label className="micro flex items-center gap-1.5">Type<select className="field h-6 w-auto py-0 font-mono text-micro uppercase" value={it.kind} onChange={(e) => patch(it.key, { kind: e.target.value })}>{FILE_KINDS.map((k) => <option key={k} value={k}>{k === 'auto' ? 'detect from content' : KIND_LABEL[k]}</option>)}</select></label>
                        {(it.kind === 'screenshot' || (it.kind === 'auto' && it.file.type.startsWith('image/'))) && (
                          <input className="field h-6 min-w-[180px] flex-1 font-mono text-micro" placeholder="URL the screenshot was captured from" value={it.sourceUrl} onChange={(e) => patch(it.key, { sourceUrl: e.target.value })} aria-label="Screenshot source URL" />
                        )}
                      </div>
                    )}
                    {it.error && <p role="alert" className="mt-1 pl-6 text-data text-threat">{it.error}</p>}
                  </li>
                ))}
              </ul>
            )}
            <div className="space-y-3 p-3">
              {error && <p role="alert" className="border-l-2 border-threat pl-2 text-data text-threat">{error}</p>}
              {phase === 'submitting' && <div role="status" className="flex items-center gap-2"><div className="relative h-px flex-1 overflow-hidden bg-line"><div className="absolute inset-y-0 w-1/4 animate-sweep bg-amber" /></div><span className="micro normal-case tracking-normal">{progress}</span></div>}
              <button className="btn-primary h-10 w-full" disabled={!canSubmit} onClick={submit}>{createdId ? 'Submit remaining evidence and analyse' : 'Create case and start analysis'}<Icon name="arrow" /></button>
              {createdId && items.some((i) => i.state === 'ok') && phase === 'edit' && <button className="btn h-9 w-full" onClick={startAccepted}>Start analysis with accepted evidence only</button>}
              {!title.trim() && items.length > 0 && <p className="micro normal-case tracking-normal">Give the case a title to launch.</p>}
            </div>
          </Panel>
          <Panel title="Handling">
            <ul className="space-y-2 p-3 text-data text-titanium">
              <li className="flex gap-2"><Icon name="shield" size={14} className="mt-0.5 shrink-0 text-cyan" />Files are identified by content, not extension, and stored read-only under a generated name.</li>
              <li className="flex gap-2"><Icon name="shield" size={14} className="mt-0.5 shrink-0 text-cyan" />Nothing you upload is executed, opened or rendered. Analysis is static.</li>
              <li className="flex gap-2"><Icon name="shield" size={14} className="mt-0.5 shrink-0 text-cyan" />Text inside evidence is treated as data. It cannot instruct the analysis.</li>
            </ul>
          </Panel>
        </div>
      </div>
    </div>
  );
}
