import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { ContainmentPanel } from '../components/ContainmentPanel'
import { useAuthStore } from '../store/auth'
import type { PlaybookExecutionResult, TenantContext } from '../types'

const mintStepUpTicketMock = vi.fn()
const revokeKeycloakSessionMock = vi.fn()
const syncDetectionToSiemMock = vi.fn()

vi.mock('../api/containment', () => ({
  mintStepUpTicket: (...args: unknown[]) => mintStepUpTicketMock(...args),
  revokeKeycloakSession: (...args: unknown[]) => revokeKeycloakSessionMock(...args),
  syncDetectionToSiem: (...args: unknown[]) => syncDetectionToSiemMock(...args),
}))

function makeUser(roles: string[]): TenantContext {
  return {
    userId: 'user-1',
    username: 'test-user',
    email: 'test-user@example.invalid',
    roles: roles as TenantContext['roles'],
    orgId: 'org-1',
    orgAlias: 'test-org',
    acr: 'aal2',
  }
}

function renderPanel(roles: string[]) {
  useAuthStore.setState({ user: makeUser(roles), accessToken: 'tok', isAuthenticated: true })
  const queryClient = new QueryClient()
  return render(
    <QueryClientProvider client={queryClient}>
      <ContainmentPanel detectionId="detection-1" />
    </QueryClientProvider>,
  )
}

function succeededResult(): PlaybookExecutionResult {
  return {
    executionId: 'exec-1',
    playbookName: 'ad-hoc-contain-revoke-keycloak-session',
    succeeded: true,
    haltedEarly: false,
    stepResults: [
      {
        stepId: 'revoke-session',
        actionName: 'revoke_keycloak_session',
        outcome: 'executed',
        output: { revoked: true },
        error: null,
      },
    ],
  }
}

function deniedResult(): PlaybookExecutionResult {
  return {
    executionId: 'exec-2',
    playbookName: 'ad-hoc-contain-revoke-keycloak-session',
    succeeded: false,
    haltedEarly: true,
    stepResults: [
      {
        stepId: 'revoke-session',
        actionName: 'revoke_keycloak_session',
        outcome: 'denied',
        output: null,
        error: 'approval denied: no valid step-up ticket',
      },
    ],
  }
}

describe('ContainmentPanel', () => {
  beforeEach(() => {
    mintStepUpTicketMock.mockReset()
    revokeKeycloakSessionMock.mockReset()
    syncDetectionToSiemMock.mockReset()
    useAuthStore.setState({ user: null, accessToken: null, isAuthenticated: false })
  })

  describe('role gating', () => {
    it('shows both sections for org-admin', () => {
      renderPanel(['org-admin'])
      expect(screen.getByRole('button', { name: /sync to siem/i })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /request approval/i })).toBeInTheDocument()
    })

    it('shows sync-to-siem but hides revoke-session controls for analyst', () => {
      renderPanel(['analyst'])
      expect(screen.getByRole('button', { name: /sync to siem/i })).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: /request approval/i })).not.toBeInTheDocument()
      expect(screen.queryByLabelText('Session ID')).not.toBeInTheDocument()
      expect(screen.getByText(/org-admin or case-lead required/i)).toBeInTheDocument()
    })

    it('hides both sections for read-only', () => {
      renderPanel(['read-only'])
      expect(screen.queryByRole('button', { name: /sync to siem/i })).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: /request approval/i })).not.toBeInTheDocument()
    })
  })

  describe('sync to SIEM', () => {
    it('calls syncDetectionToSiem with the selected sink and shows success', async () => {
      syncDetectionToSiemMock.mockResolvedValue(succeededResult())
      const user = userEvent.setup()
      renderPanel(['analyst'])

      await user.click(screen.getByRole('button', { name: /sync to siem/i }))

      await waitFor(() => {
        expect(syncDetectionToSiemMock).toHaveBeenCalledWith('detection-1', 'splunk')
      })
      expect(await screen.findByText(/succeeded/i)).toBeInTheDocument()
    })

    it('shows an honest "not configured" message on a 404', async () => {
      syncDetectionToSiemMock.mockRejectedValue({
        isAxiosError: true,
        response: { status: 404, data: { detail: 'not configured' } },
      })
      const user = userEvent.setup()
      renderPanel(['analyst'])

      await user.click(screen.getByRole('button', { name: /sync to siem/i }))

      expect(await screen.findByText(/not configured in this deployment/i)).toBeInTheDocument()
    })
  })

  describe('revoke session two-step approval flow', () => {
    it('mints a ticket scoped to sessionId, then confirms revoke with that ticket', async () => {
      mintStepUpTicketMock.mockResolvedValue('ticket-abc')
      revokeKeycloakSessionMock.mockResolvedValue(succeededResult())
      const user = userEvent.setup()
      renderPanel(['case-lead'])

      await user.type(screen.getByLabelText('User ID'), '11111111-1111-1111-1111-111111111111')
      await user.type(screen.getByLabelText('Session ID'), 'session-xyz')

      const confirmButton = screen.getByRole('button', { name: /confirm revoke/i })
      expect(confirmButton).toBeDisabled()

      await user.click(screen.getByRole('button', { name: /request approval/i }))
      await waitFor(() => {
        expect(mintStepUpTicketMock).toHaveBeenCalledWith('revoke_keycloak_session', 'session-xyz')
      })

      await waitFor(() => expect(confirmButton).toBeEnabled())
      await user.click(confirmButton)

      await waitFor(() => {
        expect(revokeKeycloakSessionMock).toHaveBeenCalledWith(
          'detection-1',
          '11111111-1111-1111-1111-111111111111',
          'session-xyz',
          'ticket-abc',
        )
      })
      expect(await screen.findByText(/succeeded/i)).toBeInTheDocument()
    })

    it('keeps Confirm Revoke disabled until a ticket has been minted', () => {
      renderPanel(['org-admin'])
      expect(screen.getByRole('button', { name: /confirm revoke/i })).toBeDisabled()
    })

    it('shows the audited denial outcome without pretending it succeeded', async () => {
      mintStepUpTicketMock.mockResolvedValue('ticket-abc')
      revokeKeycloakSessionMock.mockResolvedValue(deniedResult())
      const user = userEvent.setup()
      renderPanel(['org-admin'])

      await user.type(screen.getByLabelText('User ID'), 'user-1')
      await user.type(screen.getByLabelText('Session ID'), 'session-1')
      await user.click(screen.getByRole('button', { name: /request approval/i }))
      await waitFor(() => screen.getByRole('button', { name: /confirm revoke/i }))
      await user.click(screen.getByRole('button', { name: /confirm revoke/i }))

      expect(await screen.findByText(/approval denied/i)).toBeInTheDocument()
    })
  })
})
