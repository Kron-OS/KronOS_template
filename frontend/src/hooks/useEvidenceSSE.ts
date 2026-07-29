import { useEffect, useRef } from 'react'
import { getSSETicket } from '../api/evidence'
import type { SSEStatusEvent } from '../types'

type SSECallback = (event: SSEStatusEvent) => void

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

        // The backend (src/external/routes/sse.py) sends named SSE frames
        // ("event: status\ndata: ...", "event: ping", "event: done") --
        // EventSource.onmessage is a shorthand for addEventListener('message', ...)
        // and per the SSE spec is NEVER invoked for a frame carrying an
        // explicit event name other than "message". Using onmessage here
        // silently received zero events forever: the connection opened
        // fine (no error, no fallback to polling), but no status update
        // ever reached the callback -- the evidence list only ever refreshed
        // via a full page reload or an incidental window-focus refetch.
        es.addEventListener('status', (e) => {
          try {
            const data = JSON.parse((e as MessageEvent).data) as SSEStatusEvent
            cbRef.current(data)
          } catch {
            // malformed event — ignore
          }
        })

        // All evidence in this case reached a terminal state (COMPLETE/ERROR)
        // -- the server closes the stream deliberately. Close here instead of
        // letting EventSource auto-reconnect: the one-shot ticket was already
        // consumed, so a reconnect attempt would 401 into onerror and start
        // an unnecessary polling loop for a case with nothing left to watch.
        es.addEventListener('done', () => {
          if (openTimer) clearTimeout(openTimer)
          es?.close()
          es = null
        })

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
