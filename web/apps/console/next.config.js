/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  transpilePackages: ["@sentinel/tokens", "@sentinel/ui"],
};

module.exports = nextConfig;
