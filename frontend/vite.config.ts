import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://backend:8000',
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on('proxyRes', (proxyRes) => {
            if (proxyRes.statusCode && proxyRes.statusCode >= 300 && proxyRes.statusCode < 400) {
              const loc = proxyRes.headers['location'];
              if (loc && typeof loc === 'string' && loc.includes('backend:8000')) {
                proxyRes.headers['location'] = loc.replace('http://backend:8000', '');
              }
            }
          });
        },
      },
      '/health': {
        target: 'http://backend:8000',
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on('proxyRes', (proxyRes) => {
            if (proxyRes.statusCode && proxyRes.statusCode >= 300 && proxyRes.statusCode < 400) {
              const loc = proxyRes.headers['location'];
              if (loc && typeof loc === 'string' && loc.includes('backend:8000')) {
                proxyRes.headers['location'] = loc.replace('http://backend:8000', '');
              }
            }
          });
        },
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          charts: ['recharts'],
          query: ['@tanstack/react-query'],
        },
      },
    },
  },
});
