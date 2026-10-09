import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run build` -> dist/, which the FastAPI server serves on the same HTTPS origin as the API.
// `npm run dev` proxies /api to a locally running backend (development only).
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": { target: "https://localhost:8443", secure: false },
    },
  },
});
