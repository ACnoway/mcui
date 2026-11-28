import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../internal/master/dist',
    emptyOutDir: false,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:2053',
        changeOrigin: true,
        ws: true,
      },
      '/sub': {
        target: 'http://127.0.0.1:2053',
        changeOrigin: true,
      },
      '/install-agent.sh': {
        target: 'http://127.0.0.1:2053',
        changeOrigin: true,
      },
    },
  },
});
