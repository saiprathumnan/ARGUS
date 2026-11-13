'use client';
export default function GlobalError({ error, reset }: { error: Error; reset: () => void }) {
  return (<div role="alert" className="flex h-full flex-col items-center justify-center gap-3 p-8 text-center"><div className="micro text-threat">Interface error</div><h1 className="h-display text-[22px]">This view failed to render</h1><p className="data max-w-lg break-words text-titanium-mute">{error.message}</p><p className="max-w-md text-body text-titanium-mute">Your investigation data is on the backend and is not affected.</p><button className="btn" onClick={reset}>Reload view</button></div>);
}
