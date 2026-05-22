import { defineConfig } from 'vite'
import react, { reactCompilerPreset } from '@vitejs/plugin-react'
import babel from '@rolldown/plugin-babel'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    babel({ presets: [reactCompilerPreset()] })
  ],
  // Build output goes to exitnode/dashboard/dist for Go embedding
  build: {
    outDir: '../exitnode/dashboard/dist',
    emptyOutDir: true,
  },
  // Dev server proxies API calls to the Go backend
  server: {
    port: 5173,
    proxy: {
      '/admin/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/admin/ws': {
        target: 'ws://localhost:8080',
        ws: true,
      },
    },
  },
})
