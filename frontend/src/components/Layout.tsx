import { type ReactNode } from 'react'
import { Link } from '@tanstack/react-router'
import { keycloak } from '../keycloak'
import { useAuthStore } from '../store/auth'

interface LayoutProps {
  children: ReactNode
}

export function Layout({ children }: LayoutProps) {
  const user = useAuthStore((s) => s.user)

  return (
    <div className="flex min-h-screen flex-col bg-gray-950 text-gray-100">
      <header className="border-b border-gray-800 bg-gray-900">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3">
          <Link to="/cases" className="text-lg font-bold tracking-tight text-indigo-400">
            KronOS
          </Link>
          <nav className="flex items-center gap-6 text-sm">
            <Link
              to="/cases"
              className="text-gray-300 hover:text-white [&.active]:text-indigo-400"
            >
              Cases
            </Link>
            {user?.roles.includes('org-admin') && (
              <Link
                to="/admin/org"
                className="text-gray-300 hover:text-white [&.active]:text-indigo-400"
              >
                Admin
              </Link>
            )}
          </nav>
          <div className="flex items-center gap-4 text-sm">
            {user && (
              <span className="text-gray-400">
                {user.username}
                {user.orgAlias && (
                  <span className="ml-1 text-gray-600">/ {user.orgAlias}</span>
                )}
              </span>
            )}
            <button
              type="button"
              onClick={() => keycloak.logout()}
              className="rounded px-3 py-1.5 text-gray-400 hover:bg-gray-800 hover:text-gray-200"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6">{children}</main>
    </div>
  )
}
