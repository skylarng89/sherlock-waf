import createClient, { type Middleware } from 'openapi-fetch'
import { ApiError, networkError, problemToError } from './errors'
import type { paths } from './schema'

export const CSRF_COOKIE = '__Host-sherlock_csrf'
export const CSRF_HEADER = 'X-CSRF-Token'

/** Sign-in-flow operations whose 401 means "wrong credentials/code", not "session expired". */
const SESSION_EXEMPT = new Set([
  '/auth/login',
  '/auth/mfa',
  '/auth/mfa/enroll',
  '/auth/mfa/enroll/confirm',
  '/auth/me',
  '/auth/logout',
  '/setup/status',
  '/setup/admin',
])

type UnauthorizedHandler = () => void
let onUnauthorized: UnauthorizedHandler | undefined

/** Registered once by the app (see `installSessionExpiry`); tests may replace it. */
export function setUnauthorizedHandler(handler: UnauthorizedHandler | undefined): void {
  onUnauthorized = handler
}

export function readCsrfToken(cookies: string = document.cookie): string | undefined {
  for (const part of cookies.split(';')) {
    const [name, ...value] = part.trim().split('=')
    if (name === CSRF_COOKIE) return decodeURIComponent(value.join('='))
  }
  return undefined
}

const sessionMiddleware: Middleware = {
  onRequest({ request }) {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
      const token = readCsrfToken()
      if (token) request.headers.set(CSRF_HEADER, token)
    }
    return request
  },
  onResponse({ response, schemaPath }) {
    if (response.status === 401 && !SESSION_EXEMPT.has(schemaPath)) onUnauthorized?.()
    return response
  },
}

export interface ApiClientOptions {
  baseUrl?: string
  fetch?: (input: Request) => Promise<Response>
}

export function createApiClient(options: ApiClientOptions = {}) {
  const client = createClient<paths>({
    baseUrl: options.baseUrl ?? '/api/v1',
    credentials: 'same-origin',
    ...(options.fetch ? { fetch: options.fetch } : {}),
  })
  client.use(sessionMiddleware)
  return client
}

/** The app-wide typed client: `client.GET('/sites')`. Pages normally go through `useApi()`. */
export const client = createApiClient()

export interface ApiResult<D> {
  data: D
  /** Value of the `ETag` response header (quotes preserved), when the server sent one. */
  etag: string | undefined
  response: Response
}

interface RawResult<D> {
  data?: D
  error?: unknown
  response: Response
}

/**
 * Turns an openapi-fetch result into `{ data, etag }` or throws `ApiError`
 * (`StaleConfigError` for 412). Transport failures become `ApiError` of kind `network`.
 */
export async function unwrap<D>(request: Promise<RawResult<D>>): Promise<ApiResult<D>> {
  let result: RawResult<D>
  try {
    result = await request
  } catch (cause) {
    if (cause instanceof ApiError) throw cause
    throw networkError(cause)
  }
  const { response } = result
  if (!response.ok) throw problemToError(response, result.error)
  return {
    data: result.data as D,
    etag: response.headers.get('ETag') ?? undefined,
    response,
  }
}

/** Header fragment for optimistic-concurrency writes: `params: { header: ifMatch(etag) }`. */
export function ifMatch(etag: string): { 'If-Match': string } {
  return { 'If-Match': etag }
}
