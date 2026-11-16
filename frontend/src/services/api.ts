/**
 * Typed fetch client for the MCP-Gateway REST API.
 * - Sends the session cookie (same origin) and the CSRF token on unsafe methods.
 * - Normalises the server's error envelope into ApiError.
 * The UI never enforces security on its own. The server is the authority.
 */
export interface ErrorDetail { field: string; code: string; message?: string }

export class ApiError extends Error {
  status: number
  code: string
  details: ErrorDetail[]
  requestId?: string
  retryAfter?: number
  constructor(status: number, code: string, message: string, details: ErrorDetail[] = [], requestId?: string, retryAfter?: number) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
    this.requestId = requestId
    this.retryAfter = retryAfter
  }
}

const BASE = '/api/v1'
let csrfToken: string | null = null

export function setCsrfToken(token: string | null | undefined) { csrfToken = token ?? null }

function readCookie(name: string): string | null {
  const m = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/[-.]/g, '\\$&') + '=([^;]*)'))
  return m ? decodeURIComponent(m[1]) : null
}

type Query = Record<string, string | number | boolean | null | undefined>

export function qs(params: Query = {}): string {
  const u = new URLSearchParams()
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') u.set(k, String(v)) })
  const s = u.toString()
  return s ? `?${s}` : ''
}

let onUnauthorized: (() => void) | null = null
export function setUnauthorizedHandler(fn: () => void) { onUnauthorized = fn }

export async function request<T>(method: string, path: string, body?: unknown, opts: { raw?: boolean } = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (!['GET', 'HEAD'].includes(method)) {
    const token = csrfToken || readCookie('mgw_csrf')
    if (token) headers['X-CSRF-Token'] = token
  }
  let res: Response
  try {
    res = await fetch(BASE + path, { method, headers, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body) })
  } catch {
    throw new ApiError(0, 'NETWORK_ERROR', 'The gateway API could not be reached.')
  }
  if (opts.raw) {
    if (!res.ok) throw await toError(res)
    return res as unknown as T
  }
  if (res.status === 204) return undefined as T
  if (!res.ok && res.status !== 202) {
    const err = await toError(res)
    if (res.status === 401 && path !== '/auth/login' && onUnauthorized) onUnauthorized()
    throw err
  }
  return (await res.json()) as T
}

async function toError(res: Response): Promise<ApiError> {
  let payload: any = null
  try { payload = await res.json() } catch { /* not json */ }
  const e = payload?.error
  const retry = res.headers.get('Retry-After')
  return new ApiError(res.status, e?.code || `HTTP_${res.status}`, e?.message || res.statusText || 'Request failed',
    e?.details || [], e?.request_id || res.headers.get('X-Request-ID') || undefined, retry ? Number(retry) : undefined)
}

export const api = {
  get: <T>(path: string, params?: Query) => request<T>('GET', path + qs(params)),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {}),
  put: <T>(path: string, body: unknown) => request<T>('PUT', path, body),
  patch: <T>(path: string, body: unknown) => request<T>('PATCH', path, body),
  del: <T = void>(path: string) => request<T>('DELETE', path),
  download: async (path: string, body: unknown, fallbackName: string) => {
    const res = await request<Response>('POST', path, body, { raw: true })
    const blob = await res.blob()
    const cd = res.headers.get('Content-Disposition') || ''
    const name = /filename="([^"]+)"/.exec(cd)?.[1] || fallbackName
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = name; a.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  },
}

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) {
    const d = e.details?.length ? ` (${e.details.slice(0, 3).map(x => `${x.field}: ${x.message || x.code}`).join('; ')})` : ''
    return `${e.message}${d}`
  }
  return e instanceof Error ? e.message : 'Unexpected error'
}
