import { create } from 'zustand'
import type { TenantContext } from '../types'

interface AuthState {
  accessToken: string | null
  user: TenantContext | null
  isAuthenticated: boolean
  setAuth: (token: string, user: TenantContext) => void
  clearAuth: () => void
  updateToken: (token: string) => void
}

export const useAuthStore = create<AuthState>((set) => ({
  accessToken: null,
  user: null,
  isAuthenticated: false,
  setAuth: (token, user) => set({ accessToken: token, user, isAuthenticated: true }),
  clearAuth: () => set({ accessToken: null, user: null, isAuthenticated: false }),
  updateToken: (token) => set({ accessToken: token }),
}))
