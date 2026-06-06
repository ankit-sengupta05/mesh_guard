/**
 * useApi — Typed HTTP client hook for the AgentOps Security Mesh backend.
 *
 * Wraps fetch with:
 * - Base URL from env
 * - API key injection
 * - JSON serialization / error handling
 * - Typed response generics
 */

const BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'
const API_KEY = import.meta.env.VITE_API_KEY ?? 'dev-api-key'

interface ApiOptions extends RequestInit {
  json?: unknown
}

async function apiFetch<T>(path: string, options: ApiOptions = {}): Promise<T> {
  const { json, headers, ...rest } = options

  const res = await fetch(`${BASE_URL}${path}`, {
    ...rest,
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': API_KEY,
      ...headers,
    },
    body: json !== undefined ? JSON.stringify(json) : rest.body,
  })

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(err.error ?? err.detail ?? `HTTP ${res.status}`)
  }

  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export const api = {
  get:    <T>(path: string, opts?: ApiOptions) => apiFetch<T>(path, { method: 'GET', ...opts }),
  post:   <T>(path: string, json?: unknown, opts?: ApiOptions) => apiFetch<T>(path, { method: 'POST', json, ...opts }),
  delete: <T>(path: string, opts?: ApiOptions) => apiFetch<T>(path, { method: 'DELETE', ...opts }),
  patch:  <T>(path: string, json?: unknown, opts?: ApiOptions) => apiFetch<T>(path, { method: 'PATCH', json, ...opts }),
}

export function useApi() {
  return api
}
