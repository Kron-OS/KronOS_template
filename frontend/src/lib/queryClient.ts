import { QueryClient } from '@tanstack/react-query'

// Extracted from App.tsx so non-component code (the uploads store, which
// invalidates the 'evidence' query when a background upload finishes,
// regardless of whether the page that started it is still mounted) can
// reach the same singleton React Query uses -- see store/uploads.ts.
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})
