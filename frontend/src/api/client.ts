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
let pendingRequests: Array<() => void> = []

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

      if (!isRefreshing) {
        isRefreshing = true
        try {
          // AUTH-002/FE-2: refresh via the backend's HttpOnly-cookie proxy,
          // never keycloak.updateToken() (which would depend on
          // keycloak-js's own in-memory refresh token). refreshAccessToken
          // already handles failure (clears auth + redirects to login).
          const refreshed = await refreshAccessToken()
          if (refreshed) {
            pendingRequests.forEach((cb) => cb())
            pendingRequests = []
          }
        } finally {
          isRefreshing = false
        }
      }

      return new Promise((resolve) => {
        pendingRequests.push(() => {
          originalRequest.headers.Authorization = `Bearer ${useAuthStore.getState().accessToken}`
          resolve(apiClient(originalRequest))
        })
      })
    }

    return Promise.reject(error)
  },
)

export default apiClient
