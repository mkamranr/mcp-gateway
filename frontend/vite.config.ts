import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev server proxies the API and MCP endpoint to the gateway so cookies stay same-origin.
const target = process.env.GATEWAY_URL || 'http://127.0.0.1:8080'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target, changeOrigin: false },
      '/mcp': { target, changeOrigin: false },
      '/health': { target, changeOrigin: false },
    },
  },
  build: { sourcemap: false, chunkSizeWarningLimit: 1200 },
})
