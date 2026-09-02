/**
 * Gap Audit Milestone YYYY: closes Tier 1 item 3 of
 * `docs/HANDOFF_AND_ORCHESTRATION.md`. `apiClient`'s global response
 * interceptor (`api/client.ts`) triggers a real, full browser redirect
 * (`keycloak.login({ acrValues: 'aal2', prompt: 'login' })`) on a step-up
 * challenge -- confirmed live across three separate features (quota,
 * invite-user, update-role; Milestones TTTT/WWWW/XXXX) that this abandons
 * both the in-flight mutation AND the submitting component's own local
 * React state (a full remount on return, not a resumed session).
 *
 * Design choice made here (not the only possible one, but the smallest
 * real improvement that doesn't risk auto-firing a security-sensitive
 * mutation without a final explicit user action): stash the form's
 * current values in `sessionStorage` right before the request that might
 * need step-up is sent, so the *same tab*, after completing the redirect
 * and landing back on the app, can restore them into the form for the
 * user to review and submit again with one click -- instead of having to
 * remember and retype everything. Never auto-submits on the caller's
 * behalf. `sessionStorage` (not `localStorage`): this data should not
 * outlive the tab, and doesn't need to survive across devices/sessions.
 */

const PREFIX = "kronos.pendingStepUpForm."

export function stashPendingStepUpForm<T>(key: string, data: T): void {
  try {
    sessionStorage.setItem(PREFIX + key, JSON.stringify(data))
  } catch {
    // sessionStorage unavailable (private browsing, quota exceeded) --
    // the form simply won't be restored after a redirect, which is
    // exactly today's (pre-YYYY) behavior, not a new regression.
  }
}

/** Reads and clears the stashed value in one step -- single-use, so a
 * manual future visit to the same form never gets stale, previously
 * abandoned input silently reapplied. */
export function takePendingStepUpForm<T>(key: string): T | null {
  try {
    const raw = sessionStorage.getItem(PREFIX + key)
    if (raw === null) return null
    sessionStorage.removeItem(PREFIX + key)
    return JSON.parse(raw) as T
  } catch {
    return null
  }
}

export function clearPendingStepUpForm(key: string): void {
  try {
    sessionStorage.removeItem(PREFIX + key)
  } catch {
    // no-op -- see stashPendingStepUpForm's own comment.
  }
}
