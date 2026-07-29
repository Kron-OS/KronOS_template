import { type ReactNode, useEffect, useState } from 'react'
import { Link } from '@tanstack/react-router'
import { keycloak } from '../keycloak'
import { useAuthStore } from '../store/auth'

interface LayoutProps {
  children: ReactNode
}

function useDarkMode() {
  const [dark, setDark] = useState<boolean>(() => {
    const stored = localStorage.getItem('kronos-theme')
    if (stored) return stored === 'dark'
    return window.matchMedia('(prefers-color-scheme: dark)').matches
  })

  useEffect(() => {
    if (dark) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
    localStorage.setItem('kronos-theme', dark ? 'dark' : 'light')
  }, [dark])

  return [dark, setDark] as const
}

export function Layout({ children }: LayoutProps) {
  const user = useAuthStore((s) => s.user)
  const [dark, setDark] = useDarkMode()

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
              onClick={() => setDark((d) => !d)}
              className="rounded px-2 py-1.5 text-gray-400 hover:bg-gray-800 hover:text-gray-200"
              aria-label={dark ? 'Switch to light mode' : 'Switch to dark mode'}
              title={dark ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {dark ? '☀' : '◑'}
            </button>
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
