import { useEffect, useRef } from 'react'
import { getSSETicket } from '../api/evidence'
import type { SSEStatusEvent, SSEErrorEvent } from '../types'

type SSECallback = (event: SSEStatusEvent | SSEErrorEvent) => void

export function useEvidenceSSE(caseId: string, onEvent: SSECallback): void {
  const cbRef = useRef(onEvent)
  cbRef.current = onEvent

  useEffect(() => {
    let es: EventSource | null = null
    let pollTimer: ReturnType<typeof setInterval> | null = null
    let openTimer: ReturnType<typeof setTimeout> | null = null
    let cancelled = false

    async function connect(): Promise<void> {
      try {
        const { ticket } = await getSSETicket(caseId)
        if (cancelled) return

        es = new EventSource(
          `/api/sse/cases/${caseId}/evidence?ticket=${encodeURIComponent(ticket)}`,
        )

        openTimer = setTimeout(() => {
          if (es?.readyState !== EventSource.OPEN) {
            es?.close()
            es = null
            startPolling()
          }
        }, 10_000)

        es.onopen = () => {
          if (openTimer) clearTimeout(openTimer)
        }

        es.onmessage = (e) => {
          try {
            const data = JSON.parse(e.data) as SSEStatusEvent | SSEErrorEvent
            cbRef.current(data)
          } catch {
            // malformed event — ignore
          }
        }

        es.onerror = () => {
          if (openTimer) clearTimeout(openTimer)
          es?.close()
          es = null
          if (!cancelled) startPolling()
        }
      } catch {
        if (!cancelled) startPolling()
      }
    }

    function startPolling(): void {
      if (cancelled || pollTimer) return
      pollTimer = setInterval(async () => {
        // Polling re-fetches the ticket each cycle; actual data fetch is handled
        // by TanStack Query. This just signals to invalidate via a custom event.
        window.dispatchEvent(new CustomEvent('kronos:sse-poll', { detail: { caseId } }))
      }, 5_000)
    }

    void connect()

    return () => {
      cancelled = true
      if (openTimer) clearTimeout(openTimer)
      if (pollTimer) clearInterval(pollTimer)
      es?.close()
    }
  }, [caseId])
}
