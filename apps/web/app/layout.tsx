import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'SOC Watchfloor',
  description: 'Executive summary portal for SOC operations',
};

// Light is the default; dark is opt-in from Settings. The stamp is applied
// before paint to avoid a flash. (Matches prototype/portal.html.)
const themeBoot = `try{var t=localStorage.getItem('theme');if(t==='dark')document.documentElement.setAttribute('data-theme','dark');else if(t!=='system')document.documentElement.setAttribute('data-theme','light');}catch(e){}`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head><script dangerouslySetInnerHTML={{ __html: themeBoot }} /></head>
      <body>{children}</body>
    </html>
  );
}
