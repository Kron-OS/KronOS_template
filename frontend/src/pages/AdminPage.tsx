import { useState } from 'react'
import axios from 'axios'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getOrgUsers, inviteUser, updateUserRole, removeUser, getOrgQuota, updateOrgQuota } from '../api/admin'
import { Spinner } from '../components/Spinner'
import { ErrorBanner } from '../components/ErrorBanner'
import { ConfirmDialog } from '../components/ConfirmDialog'
import type { Role, OrgUser, InviteUserInput } from '../types'

const ROLES: Role[] = ['org-admin', 'case-lead', 'analyst', 'read-only']

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  if (bytes < 1024 * 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
  return `${(bytes / (1024 * 1024 * 1024 * 1024)).toFixed(2)} TB`
}

/**
 * `GET`/`PATCH /api/admin/org/quota` (`src/external/routes/admin.py`,
 * `docs/TENANT_USAGE_QUOTA.md`) had zero frontend UI before this --
 * confirmed via `grep -rn "Quota\|quota" frontend/src/pages/*.tsx` before
 * writing this. Setting a quota is `_assert_aal2`-gated (step-up MFA),
 * same as `updateUserRole`/`inviteUser` above -- `apiClient`'s own global
 * axios interceptor (`api/client.ts`) already transparently handles the
 * real `401` + `WWW-Authenticate: ...acr_values="aal2"` challenge for
 * every request through it, so this reuses that proven path rather than
 * building any new step-up handling.
 */
function QuotaSection() {
  const queryClient = useQueryClient()
  const [gbInput, setGbInput] = useState('')
  const { data, isLoading, error } = useQuery({
    queryKey: ['orgQuota'],
    queryFn: getOrgQuota,
    staleTime: 30_000,
  })

  const mutation = useMutation({
    mutationFn: (storageQuotaBytes: number | null) => updateOrgQuota(storageQuotaBytes),
    onSuccess: async (updated) => {
      queryClient.setQueryData(['orgQuota'], updated)
      setGbInput('')
    },
  })

  if (isLoading) return <Spinner className="mt-4" />
  if (error || !data) return <ErrorBanner message="Failed to load storage quota." />

  const percentUsed =
    data.storageQuotaBytes && data.storageQuotaBytes > 0
      ? Math.min(100, Math.round((data.currentUsageBytes / data.storageQuotaBytes) * 100))
      : null

  return (
    <div className="mb-8 max-w-md">
      <h3 className="mb-3 text-sm font-semibold text-gray-800 dark:text-gray-200">Storage Quota</h3>
      <p className="mb-1 text-sm text-gray-700 dark:text-gray-300">
        {formatBytes(data.currentUsageBytes)} used
        {data.storageQuotaBytes !== null && <> of {formatBytes(data.storageQuotaBytes)}</>}
        {data.storageQuotaBytes === null && <span className="text-gray-500"> (unlimited)</span>}
      </p>
      {percentUsed !== null && (
        <div className="mb-4 h-2 w-full overflow-hidden rounded bg-gray-200 dark:bg-gray-800">
          <div
            className={`h-full ${percentUsed >= 90 ? 'bg-red-600' : 'bg-indigo-600'}`}
            style={{ width: `${percentUsed}%` }}
          />
        </div>
      )}
      <form
        onSubmit={(e) => {
          e.preventDefault()
          const gb = Number(gbInput)
          if (gb > 0) mutation.mutate(Math.round(gb * 1024 * 1024 * 1024))
        }}
        className="flex items-center gap-2"
      >
        <label htmlFor="quota-gb-input" className="sr-only">
          New quota (GB)
        </label>
        <input
          id="quota-gb-input"
          type="number"
          min={1}
          step="any"
          value={gbInput}
          onChange={(e) => setGbInput(e.target.value)}
          placeholder="New limit (GB)"
          className="w-40 rounded border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-indigo-500 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
        />
        <button
          type="submit"
          disabled={mutation.isPending || !(Number(gbInput) > 0)}
          className="flex items-center gap-2 rounded bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-60"
        >
          {mutation.isPending && <Spinner size="sm" />}
          Save
        </button>
        {data.storageQuotaBytes !== null && (
          <button
            type="button"
            onClick={() => mutation.mutate(null)}
            disabled={mutation.isPending}
            className="rounded px-3 py-2 text-sm font-medium text-gray-600 hover:bg-gray-100 disabled:opacity-50 dark:text-gray-400 dark:hover:bg-gray-800"
          >
            Clear (unlimited)
          </button>
        )}
      </form>
      {mutation.isError && <ErrorBanner message="Failed to update storage quota." />}
    </div>
  )
}

const MIN_PASSWORD_LENGTH = 12

// Excludes visually ambiguous characters (0/O, 1/I/l) to keep generated
// passwords easy to read back when an admin communicates them out of band.
function generatePassword(length = 16): string {
  const categories = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!@#%^&*-_=+']
  const all = categories.join('')
  const randomIndex = (max: number) => {
    const buf = new Uint32Array(1)
    crypto.getRandomValues(buf)
    return buf[0] % max
  }
  const chars = Array.from({ length }, () => all[randomIndex(all.length)])
  // Guarantee at least one character from each category.
  categories.forEach((cat, i) => {
    chars[i] = cat[randomIndex(cat.length)]
  })
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1)
    ;[chars[i], chars[j]] = [chars[j], chars[i]]
  }
  return chars.join('')
}

// FastAPI's own request validation (e.g. Field(min_length=...) on the
// InviteUserIn model) returns detail as a list of {msg} objects; our
// hand-raised HTTPExceptions (e.g. Keycloak password-policy rejection)
// return detail as a plain string. Handle both.
function getErrorDetail(error: unknown, fallback: string): string {
  if (axios.isAxiosError(error)) {
    const detail: unknown = error.response?.data?.detail
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail)) {
      return detail
        .map((d) => (d && typeof d === 'object' && 'msg' in d ? String(d.msg) : JSON.stringify(d)))
        .join('; ')
    }
  }
  return fallback
}

const EMPTY_INVITE_FORM: InviteUserInput = {
  email: '',
  firstName: '',
  lastName: '',
  password: '',
  role: 'analyst',
}

function InviteModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient()
  const [form, setForm] = useState<InviteUserInput>(EMPTY_INVITE_FORM)
  const [showPassword, setShowPassword] = useState(false)
  const mutation = useMutation({
    mutationFn: () => inviteUser(form),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['orgUsers'] })
      setForm(EMPTY_INVITE_FORM)
      setShowPassword(false)
      onClose()
    },
  })

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-sm rounded-lg border border-gray-300 bg-white p-6 shadow-xl dark:border-gray-700 dark:bg-gray-900">
        <h2 className="mb-4 text-base font-semibold text-gray-900 dark:text-gray-100">Create User</h2>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            mutation.mutate()
          }}
          className="space-y-4"
        >
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400" htmlFor="invite-first-name">
                First name
              </label>
              <input
                id="invite-first-name"
                type="text"
                required
                autoComplete="given-name"
                value={form.firstName}
                onChange={(e) => setForm((f) => ({ ...f, firstName: e.target.value }))}
                className="w-full rounded border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-indigo-500 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400" htmlFor="invite-last-name">
                Last name
              </label>
              <input
                id="invite-last-name"
                type="text"
                required
                autoComplete="family-name"
                value={form.lastName}
                onChange={(e) => setForm((f) => ({ ...f, lastName: e.target.value }))}
                className="w-full rounded border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-indigo-500 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
              />
            </div>
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400" htmlFor="invite-email">
              Email
            </label>
            <input
              id="invite-email"
              type="email"
              required
              autoComplete="email"
              value={form.email}
              onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
              className="w-full rounded border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-indigo-500 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
            />
          </div>
          <div>
            <div className="mb-1 flex items-center justify-between">
              <label
                className="block text-xs font-medium text-gray-600 dark:text-gray-400"
                htmlFor="invite-password"
              >
                Initial password
              </label>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setForm((f) => ({ ...f, password: generatePassword() }))}
                  className="text-xs text-indigo-600 hover:text-indigo-500 dark:text-indigo-400 dark:hover:text-indigo-300"
                >
                  Generate
                </button>
                <button
                  type="button"
                  onClick={() => setShowPassword((s) => !s)}
                  className="text-xs text-gray-600 hover:text-gray-500 dark:text-gray-400 dark:hover:text-gray-300"
                >
                  {showPassword ? 'Hide' : 'Show'}
                </button>
              </div>
            </div>
            <input
              id="invite-password"
              type={showPassword ? 'text' : 'password'}
              required
              minLength={MIN_PASSWORD_LENGTH}
              autoComplete="new-password"
              value={form.password}
              onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
              className="w-full rounded border border-gray-300 bg-white px-3 py-2 font-mono text-sm text-gray-900 focus:border-indigo-500 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
            />
            <p className="mt-1 text-xs text-gray-500">
              At least {MIN_PASSWORD_LENGTH} characters, and cannot contain the user's email. Share this
              with the user directly — they must change it on first login.
            </p>
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400" htmlFor="invite-role">
              Role
            </label>
            <select
              id="invite-role"
              value={form.role}
              onChange={(e) => setForm((f) => ({ ...f, role: e.target.value as Role }))}
              className="w-full rounded border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-indigo-500 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100"
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>
          {mutation.isError && (
            <ErrorBanner message={getErrorDetail(mutation.error, 'Failed to create user.')} />
          )}
          <div className="flex justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="rounded px-4 py-2 text-sm text-gray-600 hover:bg-gray-200 dark:text-gray-400 dark:hover:bg-gray-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={mutation.isPending}
              className="flex items-center gap-2 rounded bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-60"
            >
              {mutation.isPending && <Spinner size="sm" />}
              Create User
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
      <tr className="hover:bg-gray-100 dark:hover:bg-gray-900/40">
        <td className="px-4 py-3 text-gray-800 dark:text-gray-200">{user.username}</td>
        <td className="px-4 py-3 text-gray-600 dark:text-gray-400">{user.email}</td>
        <td className="px-4 py-3">
          {/* Milestone JJJJ: a real axe-core `select-name` violation
              (critical impact) -- this role select had no accessible name
              at all (no <label>, no aria-label), so a screen-reader user
              landing on it had no way to know what it controlled beyond
              "combo box". `aria-label` (not a visible <label>, to avoid
              disturbing this table's existing compact layout) names it
              per-row using the real username already rendered in the
              first <td>. */}
          <select
            value={user.roles[0] ?? 'read-only'}
            onChange={(e) => roleMutation.mutate(e.target.value as Role)}
            aria-label={`Role for ${user.username}`}
            className="rounded border border-gray-300 bg-white px-2 py-1 text-xs text-gray-700 focus:border-indigo-500 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-gray-300"
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
            className="text-xs text-red-600 hover:text-red-500 dark:text-red-400 dark:hover:text-red-300"
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
        <h1 className="text-xl font-bold text-gray-900 dark:text-gray-100">Organisation Admin</h1>
        <button
          type="button"
          onClick={() => setShowInvite(true)}
          className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
        >
          Create User
        </button>
      </div>

      <QuotaSection />

      {isLoading && <div className="flex justify-center py-12"><Spinner size="lg" /></div>}
      {error && <ErrorBanner message="Failed to load users." />}

      {data && (
        <div className="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-800">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-100/50 text-left text-xs text-gray-600 dark:border-gray-800 dark:bg-gray-900/50 dark:text-gray-400">
                <th className="px-4 py-3 font-medium">Username</th>
                <th className="px-4 py-3 font-medium">Email</th>
                <th className="px-4 py-3 font-medium">Role</th>
                <th className="px-4 py-3 font-medium">Joined</th>
                <th className="px-4 py-3 font-medium"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
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
