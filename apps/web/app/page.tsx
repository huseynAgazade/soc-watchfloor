// Placeholder landing. The real app renders the shell (rail + topbar + views)
// ported from prototype/portal.html. Until then this points contributors there.
export default function Home() {
  return (
    <main style={{ maxWidth: 640, margin: '12vh auto', padding: '0 24px', fontFamily: 'system-ui' }}>
      <h1 style={{ fontSize: 20, marginBottom: 8 }}>SOC Watchfloor</h1>
      <p style={{ color: '#555', lineHeight: 1.6 }}>
        Web BFF scaffold. The approved UI reference is <code>prototype/portal.html</code>;
        views are being ported into <code>app/</code> one section at a time. The FastAPI
        core is proxied at <code>/api/core/*</code>.
      </p>
    </main>
  );
}
