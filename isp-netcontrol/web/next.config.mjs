// In production Nginx sends /api/* to the Go API and everything else here.
// For local development set API_URL (e.g. http://127.0.0.1:8080) and Next
// proxies /api/* itself.
/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
  async rewrites() {
    return process.env.API_URL ? [{ source: "/api/:path*", destination: `${process.env.API_URL}/api/:path*` }] : [];
  },
};
export default nextConfig;
