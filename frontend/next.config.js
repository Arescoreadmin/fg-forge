/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",

  // API proxy to backend services - avoids CORS issues
  async rewrites() {
    const API_URL = process.env.API_URL || "http://localhost:8082";
    const ORCH_URL = process.env.ORCH_URL || "http://localhost:8083";
    const SCORE_URL = process.env.SCORE_URL || "http://localhost:8086";

    return [
      // Spawn service
      {
        source: "/api/spawn",
        destination: `${API_URL}/v1/spawn`,
      },
      {
        source: "/api/access/:path*",
        destination: `${API_URL}/v1/access/:path*`,
      },
      // Orchestrator
      {
        source: "/api/scenarios",
        destination: `${ORCH_URL}/v1/scenarios`,
      },
      {
        source: "/api/scenarios/:path*",
        destination: `${ORCH_URL}/v1/scenarios/:path*`,
      },
      // Scoreboard
      {
        source: "/api/scores/:path*",
        destination: `${SCORE_URL}/v1/scores/:path*`,
      },
      {
        source: "/api/leaderboard/:path*",
        destination: `${SCORE_URL}/v1/leaderboard/:path*`,
      },
      {
        source: "/api/stats",
        destination: `${SCORE_URL}/v1/stats`,
      },
    ];
  },
};

module.exports = nextConfig;
