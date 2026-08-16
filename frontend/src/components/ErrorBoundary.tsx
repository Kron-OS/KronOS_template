import { Component, type ErrorInfo, type ReactNode } from 'react'

interface ErrorBoundaryProps {
  children: ReactNode
}

interface ErrorBoundaryState {
  hasError: boolean
}

/**
 * Root-level React error boundary (class component -- React has no hooks
 * equivalent for componentDidCatch/getDerivedStateFromError as of the
 * React 19 pinned in package.json). Catches render exceptions anywhere in
 * the wrapped subtree that would otherwise leave the user staring at a
 * blank white/black screen with no signal at all (P2-W13).
 *
 * Deliberately does NOT render the raw error message or stack trace to the
 * end user -- KronOS is a forensics/security product and leaking internal
 * error detail to the browser is an information-disclosure smell. The
 * error is logged via `console.error` only; this repo has no real
 * error-reporting sink (Sentry or similar) wired up today (confirmed via
 * grep across frontend/src), so inventing one is out of scope here.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false }

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { hasError: true }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('kronos:unhandled_render_error', error, errorInfo.componentStack)
  }

  private handleReload = (): void => {
    window.location.reload()
  }

  render(): ReactNode {
    if (!this.state.hasError) {
      return this.props.children
    }

    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-gray-50 px-4 text-center dark:bg-gray-950">
        <p className="text-4xl font-bold text-gray-400 dark:text-gray-600" aria-hidden="true">
          !
        </p>
        <h1 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
          Something went wrong
        </h1>
        <p className="max-w-sm text-sm text-gray-600 dark:text-gray-400">
          An unexpected error occurred while rendering this page. Reloading usually resolves
          it — if the problem persists, contact your KronOS administrator.
        </p>
        <button
          type="button"
          onClick={this.handleReload}
          className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 focus:ring-offset-white dark:focus:ring-offset-gray-950"
        >
          Reload page
        </button>
      </div>
    )
  }
}
