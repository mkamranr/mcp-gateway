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
  build: {
    sourcemap: false,
    rollupOptions: {
      output: {
        // Long-lived vendor chunks: recharts is only needed by chart pages, react/router/query by everything.
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined
          if (/recharts|d3-|victory-vendor/.test(id)) return 'charts'
          if (/react-router|@tanstack|[\\/]react(-dom)?[\\/]|scheduler/.test(id)) return 'vendor'
          return undefined
        },
      },
    },
  },
})
