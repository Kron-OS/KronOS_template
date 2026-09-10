import { useUploadsStore } from '../store/uploads'
import { Spinner } from './Spinner'

// Always-mounted (see Layout.tsx) persistent indicator for a minimized
// upload -- the actual mechanism satisfying "minimize so we can still
// navigate the site": the upload itself is driven by store/uploads.ts
// regardless of which page is showing, this just surfaces live progress
// and a way back into the drawer from anywhere.
export function UploadStatusBadge() {
  const minimized = useUploadsStore((s) => s.minimized)
  const jobs = useUploadsStore((s) => s.jobs)
  const openDrawer = useUploadsStore((s) => s.openDrawer)
  const activeCaseId = useUploadsStore((s) => s.activeCaseId)

  if (!minimized || jobs.length === 0) return null

  const active = jobs.filter((j) => j.status === 'uploading')
  const errored = jobs.filter((j) => j.status === 'error')

  let label: string
  if (active.length > 0) {
    const avgProgress = Math.round(
      active.reduce((sum, j) => sum + j.progress, 0) / active.length,
    )
    label = `Uploading ${active.length} file${active.length !== 1 ? 's' : ''}… ${avgProgress}%`
  } else if (errored.length > 0) {
    label = `${errored.length} upload${errored.length !== 1 ? 's' : ''} failed`
  } else {
    label = `${jobs.length} file${jobs.length !== 1 ? 's' : ''} uploaded`
  }

  return (
    <button
      type="button"
      onClick={() => activeCaseId && openDrawer(activeCaseId)}
      aria-label={`Upload status: ${label}. Click to reopen.`}
      className="fixed bottom-4 right-4 z-50 flex items-center gap-2 rounded-full border border-gray-300 bg-white px-4 py-2 text-xs font-medium text-gray-800 shadow-lg hover:bg-gray-100 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-200 dark:hover:bg-gray-800"
    >
      {active.length > 0 && <Spinner size="sm" />}
      {label}
    </button>
  )
}
