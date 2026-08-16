import { useEffect, useState } from 'react'

/**
 * Source of truth for the app's light/dark theme. Reads the persisted
 * choice (falling back to the OS `prefers-color-scheme`) once on mount,
 * then keeps `<html>`'s `dark` class (the Tailwind v4 `@variant dark`
 * selector declared in index.css) and localStorage in sync whenever it
 * changes.
 *
 * Called from two places on purpose:
 *   - Once at the App root (App.tsx) so the theme class is applied on
 *     every full page load regardless of route -- including /login, which
 *     never mounts <Layout>. Real browser testing (poc/frontend_theme_fix/)
 *     caught that without this, a fresh load of /login always rendered
 *     light-mode-only: the class-sync effect previously lived exclusively
 *     inside Layout, so it simply never ran on pages that don't use it.
 *   - Again inside Layout, for the actual toggle button's UI state.
 * Both instances compute the same initial value from the same synchronous
 * sources (localStorage/matchMedia) at their own mount time, so they never
 * disagree; only the instance whose setter was actually invoked re-runs
 * the sync effect afterward.
 */
export function useDarkMode() {
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
