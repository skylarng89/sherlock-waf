import { describe, expect, it } from 'vitest'
import { ApiError, StaleConfigError, isStale, problemToError } from './errors'

const res = (status: number, headers: Record<string, string> = {}) =>
  new Response(null, { status, headers })

describe('problemToError', () => {
  it('parses a problem+json document with field errors keyed by pointer', () => {
    const err = problemToError(res(422), {
      type: 'urn:sherlock:problem:validation',
      title: 'Validation failed',
      status: 422,
      detail: 'bad input',
      request_id: 'req-1',
      errors: [
        { path: '/hosts/0', code: 'invalid', message: 'not a hostname' },
        { path: '/hosts/0', code: 'dup', message: 'duplicate' },
        { path: '/name', code: 'required', message: 'required' },
      ],
    })
    expect(err).toBeInstanceOf(ApiError)
    expect(err.kind).toBe('validation')
    expect(err.code).toBe('validation')
    expect(err.requestId).toBe('req-1')
    expect(err.fieldErrors).toEqual({
      '/hosts/0': ['not a hostname', 'duplicate'],
      '/name': ['required'],
    })
    expect(err.hasFieldErrors).toBe(true)
  })

  it('maps 412 to a typed StaleConfigError', () => {
    const err = problemToError(res(412), { title: 'Precondition failed' })
    expect(err).toBeInstanceOf(StaleConfigError)
    expect(isStale(err)).toBe(true)
    expect(err.kind).toBe('stale')
  })

  it.each([
    [401, 'unauthenticated'],
    [403, 'forbidden'],
    [404, 'not_found'],
    [428, 'precondition_required'],
    [429, 'rate_limited'],
    [503, 'server'],
  ])('status %i has kind %s', (status, kind) => {
    expect(problemToError(res(status), undefined).kind).toBe(kind)
  })

  it('reads retry_after_seconds, falling back to the Retry-After header', () => {
    expect(problemToError(res(429), { retry_after_seconds: 12 }).retryAfter).toBe(12)
    expect(problemToError(res(429, { 'Retry-After': '30' }), {}).retryAfter).toBe(30)
    expect(problemToError(res(429), {}).retryAfter).toBeUndefined()
  })

  it('tolerates a missing or non-object body and uses X-Request-Id', () => {
    const err = problemToError(res(500, { 'X-Request-Id': 'hdr-1' }), 'oops')
    expect(err.requestId).toBe('hdr-1')
    expect(err.title).toBe('HTTP 500')
    expect(err.fieldErrors).toEqual({})
  })
})
