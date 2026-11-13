import Link from 'next/link';
export default function NotFound() {
  return (<div className="flex h-full flex-col items-center justify-center gap-3 p-8 text-center"><div className="micro text-amber">404</div><h1 className="h-display text-[26px]">This view does not exist</h1><p className="max-w-md text-body text-titanium-mute">The address may be mistyped, or the investigation it pointed to was deleted.</p><Link href="/history" className="btn">Investigation history</Link></div>);
}
