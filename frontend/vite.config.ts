import { defineConfig } from 'vitest/config'
import { loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  // Real, reproduced bug this default fixes: index.html's CSP <meta> tag
  // uses Vite's own %VITE_KEYCLOAK_URL% HTML interpolation (see its
  // comment for why) so it never drifts out of sync with NGINX's own CSP
  // header. But with no frontend/.env present (this repo only ships
  // .env.example, not committed as .env) and no VITE_KEYCLOAK_URL in the
  // process environment, Vite leaves the literal "%VITE_KEYCLOAK_URL%"
  // string unreplaced in the built HTML (confirmed: a real `npm run
  // build` with no .env logs "(!) %VITE_KEYCLOAK_URL% is not defined...")
  // -- a real regression for anyone running the frontend outside the
  // Docker build (which always supplies it as a build arg) without first
  // copying .env.example to .env. Falls back to the exact same
  // https://kronos.local:8443 default frontend/src/keycloak.ts's own
  // resolveKeycloakUrl() already uses when VITE_KEYCLOAK_URL is unset
  // (kronos.local is the sole authorized domain, docs/lan-dev-access.md
  // -- no localhost fallback), so an unconfigured local `vite dev`/
  // `vite build` behaves identically to the Docker build's own default;
  // real .env/build-arg values still take priority.
  if (!loadEnv(mode, process.cwd(), 'VITE_').VITE_KEYCLOAK_URL) {
    process.env.VITE_KEYCLOAK_URL = 'https://kronos.local:8443'
  }

  return {
    plugins: [tailwindcss(), react()],
    test: {
      environment: 'jsdom',
      globals: true,
      setupFiles: ['./src/__tests__/setup.ts'],
    },
  }
})
