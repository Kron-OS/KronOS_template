import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { keycloak, initKeycloak, scheduleTokenRefresh } from './keycloak'
import { useAuthStore } from './store/auth'
import { parseTenantContext } from './utils/parseTenantContext'

async function bootstrap() {
  await initKeycloak()

  if (keycloak.authenticated && keycloak.token) {
    const tenantContext = parseTenantContext(keycloak)
    useAuthStore.getState().setAuth(keycloak.token, tenantContext)
    scheduleTokenRefresh()
  }

  const root = document.getElementById('root')
  if (!root) throw new Error('Missing #root element')

  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  )
}

void bootstrap()
