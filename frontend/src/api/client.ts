import axios, { type AxiosInstance, type InternalAxiosRequestConfig } from 'axios'
import { keycloak, refreshAccessToken } from '../keycloak'
import { useAuthStore } from '../store/auth'

const API_URL = import.meta.env.VITE_API_URL ?? ''

export const apiClient: AxiosInstance = axios.create({
  baseURL: API_URL,
  headers: { 'Content-Type': 'application/json' },
})

apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = useAuthStore.getState().accessToken
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

let isRefreshing = false
// Gap Audit Milestone SS: each waiter is called with the refresh outcome so
// it can resolve (retry) or reject itself -- see the real bug this replaced
// in this function's own history for why a bare `() => void` callback array
// silently dropped requests.
let pendingRequests: Array<(refreshed: boolean) => void> = []

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    if (error.response?.status === 401) {
      const wwwAuth: string = error.response.headers['www-authenticate'] ?? ''
      if (wwwAuth.includes('acr_values="aal2"')) {
        keycloak.login({ acrValues: 'aal2', prompt: 'login' })
        return Promise.reject(error)
      }

      const retryWithFreshToken = () => {
        originalRequest.headers.Authorization = `Bearer ${useAuthStore.getState().accessToken}`
        return apiClient(originalRequest)
      }

      if (isRefreshing) {
        // Another request already triggered a refresh; queue behind it and
        // retry (or fail) once it settles, rather than starting a second,
        // redundant refresh cycle.
        return new Promise((resolve, reject) => {
          pendingRequests.push((refreshed) => (refreshed ? resolve(retryWithFreshToken()) : reject(error)))
        })
      }

      isRefreshing = true
      try {
        // AUTH-002/FE-2: refresh via the backend's HttpOnly-cookie proxy,
        // never keycloak.updateToken() (which would depend on
        // keycloak-js's own in-memory refresh token). refreshAccessToken
        // already handles failure (clears auth + redirects to login).
        const refreshed = await refreshAccessToken()
        // Real bug fixed here (Gap Audit Milestone SS): this request --
        // the one whose 401 actually triggered the refresh -- used to push
        // its OWN retry callback onto pendingRequests only after this
        // block already ran and flushed it, so it queued behind an
        // already-emptied array and hung forever, even on a successful
        // refresh. Every OTHER concurrent request queued while this one
        // was in flight got correctly retried; only the triggering request
        // itself never was. Retrying directly here (rather than queueing)
        // fixes it for the common single-request case; the queued waiters
        // above are still flushed for any requests that piled up
        // concurrently.
        pendingRequests.forEach((cb) => cb(refreshed))
        pendingRequests = []
        if (refreshed) {
          return retryWithFreshToken()
        }
        return Promise.reject(error)
      } finally {
        isRefreshing = false
      }
    }

    return Promise.reject(error)
  },
)

export default apiClient
