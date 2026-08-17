import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The API is a separate process on :8080 (`make up`). Proxying rather than
// hardcoding an origin keeps the browser on one origin, so SSE and uploads need
// no CORS config on the FastAPI side — and the frozen route surface stays
// untouched by the existence of a UI.
//
// `preview` gets the same proxy as `dev`: the demo is run from a production
// build, and a proxy that only exists in dev fails at exactly the wrong moment.
const proxy = {
  '/api': {
    target: process.env.DRISHTI_API_ORIGIN ?? 'http://127.0.0.1:8080',
    changeOrigin: true,
    // SSE must not be buffered — the live log and the stage strip are the two
    // things a judge watches move.
    ws: false,
  },
}

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { port: 5173, proxy },
  preview: { port: 4173, proxy },
})
