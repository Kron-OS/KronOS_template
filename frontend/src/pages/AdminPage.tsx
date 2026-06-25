import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getOrgUsers, inviteUser, updateUserRole, removeUser } from '../api/admin'
import { Spinner } from '../components/Spinner'
import { ErrorBanner } from '../components/ErrorBanner'
import { ConfirmDialog } from '../components/ConfirmDialog'
import type { Role, OrgUser } from '../types'

const ROLES: Role[] = ['org-admin', 'case-lead', 'analyst', 'read-only']

function InviteModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient()
  const [form, setForm] = useState({ email: '', role: 'analyst' as Role })
  const mutation = useMutation({
    mutationFn: () => inviteUser(form.email, form.role),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['orgUsers'] })
      setForm({ email: '', role: 'analyst' })
      onClose()
    },
  })

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-sm rounded-lg border border-gray-700 bg-gray-900 p-6 shadow-xl">
        <h2 className="mb-4 text-base font-semibold text-gray-100">Invite User</h2>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            mutation.mutate()
          }}
          className="space-y-4"
        >
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-400" htmlFor="invite-email">
              Email
            </label>
            <input
              id="invite-email"
              type="email"
              required
              value={form.email}
              onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100 focus:border-indigo-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-400" htmlFor="invite-role">
              Role
            </label>
            <select
              id="invite-role"
              value={form.role}
              onChange={(e) => setForm((f) => ({ ...f, role: e.target.value as Role }))}
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100 focus:border-indigo-500 focus:outline-none"
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>
          {mutation.isError && <ErrorBanner message="Failed to invite user." />}
          <div className="flex justify-end gap-3">
            <button type="button" onClick={onClose} className="rounded px-4 py-2 text-sm text-gray-400 hover:bg-gray-800">
              Cancel
            </button>
            <button
              type="submit"
              disabled={mutation.isPending}
              className="flex items-center gap-2 rounded bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-60"
            >
              {mutation.isPending && <Spinner size="sm" />}
              Invite
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function UserRow({ user }: { user: OrgUser }) {
  const queryClient = useQueryClient()
  const [confirmRemove, setConfirmRemove] = useState(false)

  const roleMutation = useMutation({
    mutationFn: (role: Role) => updateUserRole(user.userId, role),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['orgUsers'] })
    },
  })

  const removeMutation = useMutation({
    mutationFn: () => removeUser(user.userId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['orgUsers'] })
    },
  })

  return (
    <>
      <tr className="hover:bg-gray-900/40">
        <td className="px-4 py-3 text-gray-200">{user.username}</td>
        <td className="px-4 py-3 text-gray-400">{user.email}</td>
        <td className="px-4 py-3">
          <select
            value={user.roles[0] ?? 'read-only'}
            onChange={(e) => roleMutation.mutate(e.target.value as Role)}
            className="rounded border border-gray-700 bg-gray-800 px-2 py-1 text-xs text-gray-300 focus:border-indigo-500 focus:outline-none"
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>
        </td>
        <td className="px-4 py-3 text-xs text-gray-500">
          {new Date(user.joinedAt).toLocaleDateString()}
        </td>
        <td className="px-4 py-3">
          <button
            type="button"
            onClick={() => setConfirmRemove(true)}
            className="text-xs text-red-400 hover:text-red-300"
          >
            Remove
          </button>
        </td>
      </tr>
      <ConfirmDialog
        open={confirmRemove}
        title="Remove user"
        message={`Remove ${user.username} from this organisation? They will lose access immediately.`}
        confirmLabel="Remove"
        onConfirm={() => {
          setConfirmRemove(false)
          removeMutation.mutate()
        }}
        onCancel={() => setConfirmRemove(false)}
      />
    </>
  )
}

export function AdminPage() {
  const [showInvite, setShowInvite] = useState(false)
  const { data, isLoading, error } = useQuery({
    queryKey: ['orgUsers'],
    queryFn: getOrgUsers,
    staleTime: 30_000,
  })

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-100">Organisation Admin</h1>
        <button
          type="button"
          onClick={() => setShowInvite(true)}
          className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
        >
          Invite User
        </button>
      </div>

      {isLoading && <div className="flex justify-center py-12"><Spinner size="lg" /></div>}
      {error && <ErrorBanner message="Failed to load users." />}

      {data && (
        <div className="overflow-x-auto rounded-lg border border-gray-800">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 bg-gray-900/50 text-left text-xs text-gray-400">
                <th className="px-4 py-3 font-medium">Username</th>
                <th className="px-4 py-3 font-medium">Email</th>
                <th className="px-4 py-3 font-medium">Role</th>
                <th className="px-4 py-3 font-medium">Joined</th>
                <th className="px-4 py-3 font-medium"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {data.map((u: OrgUser) => (
                <UserRow key={u.userId} user={u} />
              ))}
              {data.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-10 text-center text-gray-500">No users.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      <InviteModal open={showInvite} onClose={() => setShowInvite(false)} />
    </div>
  )
}
