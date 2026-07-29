import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { initKeycloak } from './keycloak'

async function bootstrap() {
  // initKeycloak populates the auth store (access token + tenant context)
  // and schedules the next silent refresh internally when authentication
  // succeeds — see keycloak.ts for the AUTH-002 token-handling rationale.
  await initKeycloak()

  const root = document.getElementById('root')
  if (!root) throw new Error('Missing #root element')

  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  )
}

void bootstrap()
