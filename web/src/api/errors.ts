import type { components } from './schema'

export type ProblemDocument = components['schemas']['Problem'] & {
  request_id?: string
}

export type ApiErrorKind =
  | 'validation'
  | 'unauthenticated'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'stale'
  | 'precondition_required'
  | 'rate_limited'
  | 'server'
  | 'network'
  | 'unknown'

/** Server validation messages keyed by RFC 6901 JSON pointer, e.g. `/hosts/0`. */
export type FieldErrors = Record<string, string[]>

export interface ApiErrorInit {
  status: number
  type?: string
  title?: string
  detail?: string
  fieldErrors?: FieldErrors
  requestId?: string
  retryAfter?: number
}

export class ApiError extends Error {
  readonly kind: ApiErrorKind
  readonly status: number
  /** Problem type URI, e.g. `urn:sherlock:problem:forbidden`. */
  readonly type: string
  /** Last segment of `type`, e.g. `forbidden`; stable for programmatic checks. */
  readonly code: string
  readonly title: string
  readonly detail?: string
  readonly fieldErrors: FieldErrors
  readonly requestId?: string
  /** Seconds until a retry is allowed (429), from `retry_after_seconds` or `Retry-After`. */
  readonly retryAfter?: number

  constructor(init: ApiErrorInit) {
    const title = init.title ?? `HTTP ${init.status}`
    super(init.detail ?? title)
    this.name = 'ApiError'
    this.status = init.status
    this.type = init.type ?? 'about:blank'
    this.code = this.type.split(':').pop()?.split('/').pop() || 'unknown'
    this.title = title
    this.detail = init.detail
    this.fieldErrors = init.fieldErrors ?? {}
    this.requestId = init.requestId
    this.retryAfter = init.retryAfter
    this.kind = kindFor(init.status)
  }

  get hasFieldErrors(): boolean {
    return Object.keys(this.fieldErrors).length > 0
  }
}

/** A write lost an optimistic-concurrency race (412): the caller must reload and re-apply. */
export class StaleConfigError extends ApiError {
  constructor(init: ApiErrorInit) {
    super({ ...init, status: 412 })
    this.name = 'StaleConfigError'
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError
}

export function isStale(e: unknown): e is StaleConfigError {
  return e instanceof StaleConfigError
}

function kindFor(status: number): ApiErrorKind {
  switch (status) {
    case 0:
      return 'network'
    case 400:
    case 422:
      return 'validation'
    case 401:
      return 'unauthenticated'
    case 403:
      return 'forbidden'
    case 404:
      return 'not_found'
    case 409:
      return 'conflict'
    case 412:
      return 'stale'
    case 428:
      return 'precondition_required'
    case 429:
      return 'rate_limited'
    default:
      return status >= 500 ? 'server' : 'unknown'
  }
}

export function networkError(cause?: unknown): ApiError {
  const err = new ApiError({ status: 0, title: 'Network error' })
  if (cause !== undefined) err.cause = cause
  return err
}

/** Builds an ApiError from a non-2xx response and its (already parsed, possibly absent) body. */
export function problemToError(response: Response, body: unknown): ApiError {
  const problem = isRecord(body) ? (body as Partial<ProblemDocument>) : {}
  const fieldErrors: FieldErrors = {}
  for (const item of Array.isArray(problem.errors) ? problem.errors : []) {
    if (isRecord(item) && typeof item.path === 'string' && typeof item.message === 'string') {
      ;(fieldErrors[item.path] ??= []).push(item.message)
    }
  }
  const header = Number(response.headers.get('Retry-After'))
  const retryAfter =
    typeof problem.retry_after_seconds === 'number'
      ? problem.retry_after_seconds
      : Number.isFinite(header) && response.headers.get('Retry-After') !== null
        ? header
        : undefined
  const init: ApiErrorInit = {
    status: response.status,
    type: typeof problem.type === 'string' ? problem.type : undefined,
    title: typeof problem.title === 'string' ? problem.title : undefined,
    detail: typeof problem.detail === 'string' ? problem.detail : undefined,
    fieldErrors,
    requestId:
      (typeof problem.request_id === 'string' ? problem.request_id : undefined) ??
      response.headers.get('X-Request-Id') ??
      undefined,
    retryAfter,
  }
  return response.status === 412 ? new StaleConfigError(init) : new ApiError(init)
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}
