import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    // The bundle is embedded in the daemon binary, so keep it to a handful of
    // files rather than a hashed sprawl the Rust side has to enumerate.
    outDir: 'dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 900,
  },
  server: {
    // `npm run dev` talks to a daemon on its usual port; the cookie is
    // SameSite=Strict, so the dev server has to proxy rather than cross-origin.
    proxy: {
      '/api': { target: 'http://127.0.0.1:8080', changeOrigin: false },
      '/healthz': { target: 'http://127.0.0.1:8080', changeOrigin: false },
    },
  },
})
