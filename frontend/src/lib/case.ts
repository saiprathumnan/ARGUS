'use client';
import { useEffect, useRef, useState } from 'react';
import { api, useApi } from './api';
import type { Finding, Graph, InvDetail, PipelineEvent } from './types';

/** Live state of one investigation. Everything here is polled from the backend; nothing is simulated client-side. */
export function useCase(id: string) {
  const inv = useApi<InvDetail>(`/investigations/${id}`, 1500);
  const running = inv.data?.status === 'running';
  const [events, setEvents] = useState<PipelineEvent[]>([]);
  const last = useRef(0);
  const epoch = useRef<string | null>(null);

  useEffect(() => { setEvents([]); last.current = 0; }, [id]);
  // a re-run wipes pipeline events server-side: restart the stream when started_at changes
  useEffect(() => {
    const s = inv.data?.started_at ?? null;
    if (epoch.current !== null && s !== epoch.current) { setEvents([]); last.current = 0; }
    epoch.current = s;
  }, [inv.data?.started_at]);
  useEffect(() => {
    let alive = true;
    const pull = () => api<{ events: PipelineEvent[] }>(`/investigations/${id}/events?after=${last.current}`).then((r) => {
      if (!alive || !r.events.length) return;
      last.current = r.events[r.events.length - 1].id;
      setEvents((p) => [...p, ...r.events.filter((e) => !p.some((x) => x.id === e.id))]);
    }).catch(() => undefined);
    pull();
    const t = setInterval(pull, running ? 900 : 5000);
    return () => { alive = false; clearInterval(t); };
  }, [id, running]);

  // derived data is refetched whenever the backend reports new counts or a status change
  const stamp = inv.data ? `${inv.data.status}:${inv.data.stage}:${inv.data.counts.indicators}:${inv.data.counts.findings}:${inv.data.counts.relationships}:${inv.data.started_at}` : '';
  const [graph, setGraph] = useState<Graph | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  useEffect(() => {
    if (!stamp) return;
    let alive = true;
    api<Graph>(`/investigations/${id}/graph`).then((g) => alive && setGraph(g)).catch(() => undefined);
    api<Finding[]>(`/investigations/${id}/findings`).then((f) => alive && setFindings(f)).catch(() => undefined);
    return () => { alive = false; };
  }, [id, stamp]);
  return { inv, events, graph, findings, running };
}
