import type { Metadata, Viewport } from 'next';
import '@fontsource/space-grotesk/400.css';
import '@fontsource/space-grotesk/500.css';
import '@fontsource/space-grotesk/600.css';
import '@fontsource/inter/400.css';
import '@fontsource/inter/500.css';
import '@fontsource/inter/600.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import './globals.css';
import { AppShell } from '@/components/shell/AppShell';

export const metadata: Metadata = { title: 'ARGUS', description: 'Autonomous Digital Investigation & Threat Intelligence Engine' };
export const viewport: Viewport = { themeColor: '#080A0E', width: 'device-width', initialScale: 1 };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (<html lang="en"><body><AppShell>{children}</AppShell></body></html>);
}
