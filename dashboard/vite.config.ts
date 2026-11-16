import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// In development the API runs on :8000; requests to /v1 are proxied so no CORS setup is needed.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: { "/v1": "http://127.0.0.1:8000" } },
  test: { environment: "node" },
});
