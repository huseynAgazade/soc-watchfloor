/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The BFF proxies the FastAPI core; the browser never talks to core directly.
  async rewrites() {
    return [
      { source: '/api/core/:path*', destination: `${process.env.CORE_BASE_URL || 'http://core:8000'}/:path*` },
    ];
  },
};
export default nextConfig;
