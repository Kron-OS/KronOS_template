import {
  createRouter,
  createRoute,
  createRootRoute,
  RouterProvider,
  Outlet,
  Navigate,
} from '@tanstack/react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ErrorBoundary } from './components/ErrorBoundary'
import { Layout } from './components/Layout'
import { useDarkMode } from './hooks/useDarkMode'
import { AuthGuard } from './components/AuthGuard'
import { RbacGuard } from './components/RbacGuard'
import { LoginPage } from './pages/LoginPage'
import { CasesPage } from './pages/CasesPage'
import { CaseDetailPage } from './pages/CaseDetailPage'
import { AdminPage } from './pages/AdminPage'
import { DetectionsPage } from './pages/DetectionsPage'
import { DetectionDetailPage } from './pages/DetectionDetailPage'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

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

const routeTree = rootRoute.addChildren([
  loginRoute,
  indexRoute,
  casesRoute,
  caseDetailRoute,
  detectionsRoute,
  detectionDetailRoute,
  adminRoute,
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
