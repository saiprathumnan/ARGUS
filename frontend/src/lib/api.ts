'use client';
import { useCallback, useEffect, useRef, useState } from 'react';

/** All requests go to the same-origin /api proxy (src/app/api/[...path]/route.ts). The backend URL and
 *  API key live only in the Next.js server environment and never reach the browser. */
export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`/api${path}`, { ...init, headers: init?.body && !(init.body instanceof FormData) ? { 'Content-Type': 'application/json', ...(init?.headers || {}) } : init?.headers, cache: 'no-store' });
  } catch {
    throw new ApiError(0, 'ARGUS interface server is unreachable.');
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let body: any = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  if (!res.ok) {
    const detail = body?.detail;
    const msg = typeof detail === 'string' ? detail : Array.isArray(detail) ? detail.map((d: any) => `${(d.loc || []).slice(1).join('.')}: ${d.msg}`).join('; ') : `Request failed (${res.status})`;
    throw new ApiError(res.status, msg);
  }
  return body as T;
}

export interface Query<T> { data: T | null; error: ApiError | null; loading: boolean; reload: () => void }

/** Fetch with optional polling. `path = null` disables the query. */
export function useApi<T>(path: string | null, pollMs = 0): Query<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(!!path);
  const alive = useRef(true);
  const load = useCallback(() => {
    if (!path) return;
    api<T>(path).then((d) => { if (alive.current) { setData(d); setError(null); } })
      .catch((e) => { if (alive.current) setError(e instanceof ApiError ? e : new ApiError(0, String(e))); })
      .finally(() => { if (alive.current) setLoading(false); });
  }, [path]);
  useEffect(() => {
    alive.current = true;
    setLoading(!!path);
    if (!path) { setData(null); return; }
    load();
    const t = pollMs ? setInterval(load, pollMs) : null;
    return () => { alive.current = false; if (t) clearInterval(t); };
  }, [path, pollMs, load]);
  // `loading` is also true on the render between a path becoming non-null and the first fetch starting
  return { data, error, loading: loading || (!!path && data === null && error === null), reload: load };
}

/** Small persisted state (per-investigation view settings survive reloads and navigation). */
export function usePersisted<T>(key: string, initial: T): [T, (v: T | ((p: T) => T)) => void] {
  const [value, setValue] = useState<T>(initial);
  const loaded = useRef(false);
  useEffect(() => {
    try { const raw = localStorage.getItem(key); if (raw !== null) setValue(JSON.parse(raw)); } catch { /* storage unavailable */ }
    loaded.current = true;
  }, [key]);
  const set = useCallback((v: T | ((p: T) => T)) => {
    setValue((prev) => {
      const next = typeof v === 'function' ? (v as (p: T) => T)(prev) : v;
      try { localStorage.setItem(key, JSON.stringify(next)); } catch { /* ignore */ }
      return next;
    });
  }, [key]);
  return [value, set];
}

export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(mq.matches);
    const h = (e: MediaQueryListEvent) => setReduced(e.matches);
    mq.addEventListener('change', h);
    return () => mq.removeEventListener('change', h);
  }, []);
  return reduced;
}

export function webglAvailable(): boolean {
  try {
    const c = document.createElement('canvas');
    return !!(window.WebGLRenderingContext && (c.getContext('webgl2') || c.getContext('webgl')));
  } catch { return false; }
}
