import { type ReactNode } from 'react'
import { useAuthStore } from '../store/auth'
import type { Role } from '../types'

interface RbacGuardProps {
  children: ReactNode
  requiredRole: Role
}

export function RbacGuard({ children, requiredRole }: RbacGuardProps) {
  const user = useAuthStore((s) => s.user)

  if (!user?.roles.includes(requiredRole)) {
    return (
      <div className="flex h-64 flex-col items-center justify-center gap-2 text-gray-400">
        <p className="text-4xl font-bold text-gray-600">403</p>
        <p className="text-sm">You do not have permission to view this page.</p>
      </div>
    )
  }

  return <>{children}</>
}
