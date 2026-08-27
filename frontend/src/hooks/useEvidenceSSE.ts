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

    // Gap Audit 2026-08-28 (frontend<->backend connectivity initiative):
    // real bug found via a real Playwright E2E run (frontend/e2e/evidence-retry.spec.ts)
    // cross-checked against real backend logs -- retrying ERROR evidence
    // (POST retry-intake/retry-parse) genuinely recovers to COMPLETE on
    // the backend, but the UI never showed it. Root cause: the `done`
    // handler below (correctly) closes the stream once ALL evidence is
    // terminal, per src/external/routes/sse.py's own "stop streaming once
    // all evidence is terminal" behavior -- but nothing ever reopens it.
    // A retry un-terminates evidence server-side with no client-side
    // signal to reconnect, so the UI sat frozen on the stale ERROR state
    // forever (not even the poll fallback runs -- that's only wired to
    // the onerror path, not `done`). Fixed by reusing the same
    // CustomEvent bridge `kronos:sse-poll` already established for the
    // polling fallback: EvidenceDetailDrawer's retry mutation now also
    // dispatches `kronos:sse-reconnect` on success, which tears down
    // whatever's currently running (open connection or poll timer) and
    // opens a fresh SSE connection with a fresh ticket.
    function handleReconnectRequest(e: Event): void {
      const detail = (e as CustomEvent<{ caseId: string }>).detail
      if (!detail || detail.caseId !== caseId || cancelled) return
      if (openTimer) clearTimeout(openTimer)
      if (pollTimer) clearInterval(pollTimer)
      pollTimer = null
      es?.close()
      es = null
      void connect()
    }
    window.addEventListener('kronos:sse-reconnect', handleReconnectRequest)

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
      pollTimer = setInterval(() => {
        // Gap Audit Milestone YY: this never re-fetches an SSE ticket (the
        // fallback path abandons SSE entirely, not just the current
        // connection) -- it only dispatches a DOM event; CaseDetailPage.tsx's
        // own listener turns that into a plain REST invalidateQueries() call.
        window.dispatchEvent(new CustomEvent('kronos:sse-poll', { detail: { caseId } }))
      }, 5_000)
    }

    void connect()

    return () => {
      cancelled = true
      window.removeEventListener('kronos:sse-reconnect', handleReconnectRequest)
      if (openTimer) clearTimeout(openTimer)
      if (pollTimer) clearInterval(pollTimer)
      es?.close()
    }
  }, [caseId])
}
