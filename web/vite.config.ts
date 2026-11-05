import { fileURLToPath, URL } from 'node:url'
import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  build: {
    // Emitted into the Go embed directory. Not emptied by Vite so the tracked
    // .gitkeep survives; `make web` cleans stale assets first.
    outDir: '../internal/webui/dist',
    emptyOutDir: false,
  },
  test: {
    environment: 'happy-dom',
    include: ['src/**/*.test.ts'],
  },
})
