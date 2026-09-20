import {
  createRouter,
  createRoute,
  createRootRoute,
  RouterProvider,
  Outlet,
  Navigate,
} from '@tanstack/react-router'
import { QueryClientProvider } from '@tanstack/react-query'
import { queryClient } from './lib/queryClient'
import { ErrorBoundary } from './components/ErrorBoundary'
import { Layout } from './components/Layout'
import { useDarkMode } from './hooks/useDarkMode'
import { AuthGuard } from './components/AuthGuard'
import { RbacGuard } from './components/RbacGuard'
import { LoginPage } from './pages/LoginPage'
import { CasesPage } from './pages/CasesPage'
import { CaseDetailPage } from './pages/CaseDetailPage'
import { AdminPage } from './pages/AdminPage'
import { ConnectorMarketplacePage } from './pages/ConnectorMarketplacePage'
import { DetectionsPage } from './pages/DetectionsPage'
import { DetectionDetailPage } from './pages/DetectionDetailPage'
import type { DetectionTriageState } from './types'

// Milestone IIIII: real, validated search-param schemas for Cases/Detections
// filtering -- URL search params are the persistence mechanism for "see
// another view" (bookmarkable/shareable/back-forward-navigable), rather
// than a separate saved-views subsystem. Parsed defensively (a hand-edited
// or stale bookmarked URL can contain anything) rather than trusted as-is.
export interface CasesSearch {
  q?: string
  status?: 'open' | 'closed' | 'archived'
  classification?: string
  sortBy?: 'createdAt' | 'updatedAt' | 'title'
  sortOrder?: 'asc' | 'desc'
  page?: number
}

const CASE_STATUSES = new Set(['open', 'closed', 'archived'])
const CASE_SORT_FIELDS = new Set(['createdAt', 'updatedAt', 'title'])

function validateCasesSearch(search: Record<string, unknown>): CasesSearch {
  return {
    q: typeof search.q === 'string' ? search.q : undefined,
    status:
      typeof search.status === 'string' && CASE_STATUSES.has(search.status)
        ? (search.status as CasesSearch['status'])
        : undefined,
    classification: typeof search.classification === 'string' ? search.classification : undefined,
    sortBy:
      typeof search.sortBy === 'string' && CASE_SORT_FIELDS.has(search.sortBy)
        ? (search.sortBy as CasesSearch['sortBy'])
        : undefined,
    sortOrder: search.sortOrder === 'asc' || search.sortOrder === 'desc' ? search.sortOrder : undefined,
    page: parsePageParam(search.page),
  }
}

export interface DetectionsSearch {
  triageState?: DetectionTriageState[]
  severity?: string[]
  caseId?: string
  q?: string
  dateFrom?: string
  dateTo?: string
  page?: number
}

const TRIAGE_STATES = new Set(['NEW', 'INVESTIGATING', 'TRUE_POSITIVE', 'FALSE_POSITIVE'])

function validateDetectionsSearch(search: Record<string, unknown>): DetectionsSearch {
  return {
    triageState: parseStringArray(search.triageState)?.filter((s) => TRIAGE_STATES.has(s)) as
      | DetectionTriageState[]
      | undefined,
    severity: parseStringArray(search.severity),
    caseId: typeof search.caseId === 'string' ? search.caseId : undefined,
    q: typeof search.q === 'string' ? search.q : undefined,
    dateFrom: typeof search.dateFrom === 'string' ? search.dateFrom : undefined,
    dateTo: typeof search.dateTo === 'string' ? search.dateTo : undefined,
    page: parsePageParam(search.page),
  }
}

function parsePageParam(value: unknown): number | undefined {
  if (typeof value === 'number') return value
  if (typeof value === 'string' && value.trim() !== '') {
    const n = Number(value)
    return Number.isFinite(n) ? n : undefined
  }
  return undefined
}

function parseStringArray(value: unknown): string[] | undefined {
  if (Array.isArray(value)) {
    const items = value.filter((v): v is string => typeof v === 'string')
    return items.length > 0 ? items : undefined
  }
  if (typeof value === 'string' && value.length > 0) return [value]
  return undefined
}

const rootRoute = createRootRoute({
  component: () => <Outlet />,
})

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: LoginPage,
})

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: () => <Navigate to="/cases" replace />,
})

const casesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/cases',
  validateSearch: validateCasesSearch,
  component: () => (
    <AuthGuard>
      <Layout>
        <CasesPage />
      </Layout>
    </AuthGuard>
  ),
})

const caseDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/cases/$caseId',
  component: () => (
    <AuthGuard>
      <Layout>
        <CaseDetailPage />
      </Layout>
    </AuthGuard>
  ),
})

const detectionsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/detections',
  validateSearch: validateDetectionsSearch,
  component: () => (
    <AuthGuard>
      <Layout>
        <DetectionsPage />
      </Layout>
    </AuthGuard>
  ),
})

const detectionDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/detections/$detectionId',
  component: () => (
    <AuthGuard>
      <Layout>
        <DetectionDetailPage />
      </Layout>
    </AuthGuard>
  ),
})

const adminRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/admin/org',
  component: () => (
    <AuthGuard>
      <RbacGuard requiredRole="org-admin">
        <Layout>
          <AdminPage />
        </Layout>
      </RbacGuard>
    </AuthGuard>
  ),
})

const connectorStatusRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/admin/connectors',
  component: () => (
    <AuthGuard>
      <RbacGuard requiredRole="org-admin">
        <Layout>
          <ConnectorMarketplacePage />
        </Layout>
      </RbacGuard>
    </AuthGuard>
  ),
})

const routeTree = rootRoute.addChildren([
  loginRoute,
  indexRoute,
  casesRoute,
  caseDetailRoute,
  detectionsRoute,
  detectionDetailRoute,
  adminRoute,
  connectorStatusRoute,
])

const router = createRouter({ routeTree })

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}

export default function App() {
  // Applies/persists the light/dark theme class on <html> unconditionally,
  // on every route -- see hooks/useDarkMode.ts for why this can't live
  // solely inside Layout (real browser verification caught /login
  // rendering light-only otherwise, since Layout never mounts there).
  useDarkMode()

  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </ErrorBoundary>
  )
}
