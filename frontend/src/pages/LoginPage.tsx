import { Navigate } from '@tanstack/react-router'
import { keycloak } from '../keycloak'
import { useAuthStore } from '../store/auth'

export function LoginPage() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)

  if (isAuthenticated) {
    return <Navigate to="/cases" replace />
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950">
      <div className="w-full max-w-sm rounded-lg border border-gray-800 bg-gray-900 p-8 text-center shadow-xl">
        <h1 className="mb-1 text-2xl font-bold tracking-tight text-indigo-400">KronOS</h1>
        <p className="mb-8 text-sm text-gray-400">Forensic Evidence Management</p>
        <button
          type="button"
          onClick={() => keycloak.login({ redirectUri: window.location.origin + '/cases' })}
          className="w-full rounded-md bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 focus:ring-offset-gray-900"
        >
          Sign in with SSO
        </button>
      </div>
    </div>
  )
}
