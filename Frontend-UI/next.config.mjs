/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  experimental: {
    serverActions: {
      allowedOrigins: ['*']
    }
  },
  typescript: {
    // We'll handle type checking in CI/CD
    ignoreBuildErrors: true
  },
  eslint: {
    // We'll handle linting in CI/CD
    ignoreDuringBuilds: true
  },
  env: {
    BACKEND_URL: process.env.BACKEND_URL || 'https://hr-agent-backend-1080649900100.me-central1.run.app'
  }
}

export default nextConfig
