interface ErrorBannerProps {
  message: string
  diagnosticId?: string
}

export function ErrorBanner({ message, diagnosticId }: ErrorBannerProps) {
  return (
    <div
      role="alert"
      className="rounded-lg border border-red-700 bg-red-950 px-4 py-3 text-sm text-red-200"
    >
      <p className="font-medium">{message}</p>
      {diagnosticId && (
        <p className="mt-1 font-mono text-xs text-red-400">ID: {diagnosticId}</p>
      )}
    </div>
  )
}
