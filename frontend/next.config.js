/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: "/api/v1/:path*",
        destination: "http://localhost:8000/api/v1/:path*",
      },
    ];
  },
  webpack: (config, { dev }) => {
    if (dev) {
      config.watchOptions = {
        ...config.watchOptions,
        ignored: [
          '**/node_modules/**',
          '**/.next/**',
          '**/backend/**',
          '**/reports/**',
          '**/guardian/**',
          '**/data/**',
          '**/docs/**',
          '**/graphify-out/**',
          '**/.venv/**',
        ],
      };
    }
    return config;
  },
};

module.exports = nextConfig;
