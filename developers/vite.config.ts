import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/developers/',
  build: {
    outDir: '../public/developers',
    emptyOutDir: true,
    sourcemap: true,
  },
});
