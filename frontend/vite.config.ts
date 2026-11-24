import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

// Vite + React + TS SPA. The UI talks to the FastAPI backend on 127.0.0.1:8000
// directly (absolute base URL + CORS on the backend), so no proxy is needed.
export default defineConfig({
  plugins: [react()],
  root: '.',
  base: './',
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        // Keep the framework in long-lived vendor chunks. Pages are lazy-loaded in App.tsx,
        // so each route becomes its own chunk alongside these. A function (not the object
        // form) also catches subpath imports such as react-dom/client and react/jsx-runtime.
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined;
          if (id.includes('react-router')) return 'router';
          if (id.includes('react-dom') || id.includes('react/') || id.includes('\\react\\')) return 'react';
          return 'vendor';
        },
      },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
  },
  clearScreen: false,
});