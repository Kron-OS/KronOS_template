import {
  createRouter,
  createRoute,
  createRootRoute,
  RouterProvider,
  Outlet,
  Navigate,
} from '@tanstack/react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Layout } from './components/Layout'
import { AuthGuard } from './components/AuthGuard'
import { RbacGuard } from './components/RbacGuard'
import { LoginPage } from './pages/LoginPage'
import { CasesPage } from './pages/CasesPage'
import { CaseDetailPage } from './pages/CaseDetailPage'
import { AdminPage } from './pages/AdminPage'

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
  adminRoute,
])

const router = createRouter({ routeTree })

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
}
