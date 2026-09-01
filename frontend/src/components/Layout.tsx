import { type ReactNode } from 'react'
import { Link } from '@tanstack/react-router'
import { keycloak } from '../keycloak'
import { useAuthStore } from '../store/auth'
import { useDarkMode } from '../hooks/useDarkMode'

interface LayoutProps {
  children: ReactNode
}

export function Layout({ children }: LayoutProps) {
  const user = useAuthStore((s) => s.user)
  const [dark, setDark] = useDarkMode()

  return (
    <div className="flex min-h-screen flex-col bg-gray-50 text-gray-900 dark:bg-gray-950 dark:text-gray-100">
      <header className="border-b border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3">
          <Link
            to="/cases"
            className="text-lg font-bold tracking-tight text-indigo-600 dark:text-indigo-400"
          >
            KronOS
          </Link>
          <nav className="flex items-center gap-6 text-sm">
            <Link
              to="/cases"
              className="text-gray-600 hover:text-gray-900 [&.active]:text-indigo-600 dark:text-gray-300 dark:hover:text-white dark:[&.active]:text-indigo-400"
            >
              Cases
            </Link>
            <Link
              to="/detections"
              className="text-gray-600 hover:text-gray-900 [&.active]:text-indigo-600 dark:text-gray-300 dark:hover:text-white dark:[&.active]:text-indigo-400"
            >
              Detections
            </Link>
            {user?.roles.includes('org-admin') && (
              <Link
                to="/admin/org"
                className="text-gray-600 hover:text-gray-900 [&.active]:text-indigo-600 dark:text-gray-300 dark:hover:text-white dark:[&.active]:text-indigo-400"
              >
                Admin
              </Link>
            )}
            {user?.roles.includes('org-admin') && (
              <Link
                to="/admin/connectors"
                className="text-gray-600 hover:text-gray-900 [&.active]:text-indigo-600 dark:text-gray-300 dark:hover:text-white dark:[&.active]:text-indigo-400"
              >
                Connectors
              </Link>
            )}
          </nav>
          <div className="flex items-center gap-4 text-sm">
            {user && (
              <span className="text-gray-600 dark:text-gray-400">
                {user.username}
                {/* Milestone JJJJ: a real axe-core color-contrast (AA) failure --
                    text-gray-400-on-white was 2.6:1, well under the 4.5:1
                    minimum; text-gray-600-on-gray-900 (the old dark: value)
                    was also under threshold (2.35:1). Swapped to match this
                    file's own established light/dark muted-text convention
                    (line 57 above), which passes both (7.56:1 light, 6.82:1
                    dark). */}
                {user.orgAlias && (
                  <span className="ml-1 text-gray-600 dark:text-gray-400">/ {user.orgAlias}</span>
                )}
              </span>
            )}
            <button
              type="button"
              onClick={() => setDark((d) => !d)}
              className="rounded px-2 py-1.5 text-gray-600 hover:bg-gray-200 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-gray-200"
              aria-label={dark ? 'Switch to light mode' : 'Switch to dark mode'}
              title={dark ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {dark ? '☀' : '◑'}
            </button>
            <button
              type="button"
              onClick={() => keycloak.logout()}
              className="rounded px-3 py-1.5 text-gray-600 hover:bg-gray-200 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-gray-200"
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
