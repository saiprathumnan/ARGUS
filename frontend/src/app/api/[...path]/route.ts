import { NextRequest } from 'next/server';

/** Server-side proxy to the ARGUS backend. Keeps the backend address and API key out of the browser. */
const BACKEND = (process.env.ARGUS_BACKEND_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');
const KEY = process.env.ARGUS_API_KEY || '';
export const dynamic = 'force-dynamic';

async function forward(req: NextRequest, { params }: { params: { path: string[] } }) {
  const segs = params.path.map((s) => encodeURIComponent(s));
  if (segs.some((s) => s === '..' || s === '.')) return Response.json({ detail: 'invalid path' }, { status: 400 });
  const url = `${BACKEND}/api/${segs.join('/')}${req.nextUrl.search}`;
  const headers = new Headers();
  const ct = req.headers.get('content-type');
  if (ct) headers.set('content-type', ct);
  if (KEY) headers.set('x-api-key', KEY);
  const hasBody = !['GET', 'HEAD'].includes(req.method);
  try {
    const res = await fetch(url, { method: req.method, headers, body: hasBody ? await req.arrayBuffer() : undefined, cache: 'no-store', redirect: 'manual' });
    const out = new Headers();
    for (const h of ['content-type', 'content-disposition', 'retry-after']) { const v = res.headers.get(h); if (v) out.set(h, v); }
    out.set('cache-control', 'no-store');
    return new Response(res.status === 204 ? null : res.body, { status: res.status, headers: out });
  } catch {
    return Response.json({ detail: 'ARGUS backend is unreachable. Start it with `uvicorn app.main:app` (see SETUP.md).' }, { status: 502 });
  }
}
export { forward as GET, forward as POST, forward as DELETE };
