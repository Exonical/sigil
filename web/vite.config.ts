/// <reference types="vitest/config" />
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";

// The portal API and config come from the backend's HTTPS listener. The dev server proxies them so the
// browser stays on one origin. The backend certificate is self-signed in development.
const backend = process.env.SIGIL_PORTAL_BACKEND ?? "https://localhost:8444";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/sigil.admin.v1.AdminService": { target: backend, changeOrigin: true, secure: false },
      "/portal-config.json": { target: backend, changeOrigin: true, secure: false },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    cssCodeSplit: false,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
