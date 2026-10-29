import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, isStale } from './errors'
import {
  CSRF_COOKIE,
  createApiClient,
  ifMatch,
  readCsrfToken,
  setUnauthorizedHandler,
  unwrap,
} from './client'

function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

describe('api client', () => {
  const fetchMock = vi.fn<(r: Request) => Promise<Response>>()
  const client = createApiClient({ fetch: fetchMock, baseUrl: 'http://localhost/api/v1' })

  beforeEach(() => {
    fetchMock.mockReset()
    // happy-dom refuses to store `__Host-` cookies (they need Secure), so stub the getter.
    vi.spyOn(document, 'cookie', 'get').mockReturnValue(`${CSRF_COOKIE}=tok%20en`)
  })
  afterEach(() => {
    setUnauthorizedHandler(undefined)
    vi.restoreAllMocks()
  })

  it('reads the CSRF cookie', () => {
    expect(readCsrfToken('a=1; __Host-sherlock_csrf=abc%3D; b=2')).toBe('abc=')
    expect(readCsrfToken('a=1')).toBeUndefined()
  })

  it('sends X-CSRF-Token on writes but not on reads', async () => {
    fetchMock.mockResolvedValue(json(200, { setup_required: false }))
    await client.GET('/setup/status')
    expect(fetchMock.mock.calls[0]?.[0].headers.get('X-CSRF-Token')).toBeNull()

    fetchMock.mockResolvedValue(json(204, null))
    await client.POST('/auth/logout')
    expect(fetchMock.mock.calls[1]?.[0].headers.get('X-CSRF-Token')).toBe('tok en')
  })

  it('unwrap returns data and etag, and ifMatch builds the header', async () => {
    fetchMock.mockResolvedValue(json(200, { items: [] }, { ETag: '"v7"' }))
    const { data, etag } = await unwrap(client.GET('/sites'))
    expect(data).toEqual({ items: [] })
    expect(etag).toBe('"v7"')
    expect(ifMatch(etag as string)).toEqual({ 'If-Match': '"v7"' })
  })

  it('unwrap throws a typed ApiError with field errors', async () => {
    fetchMock.mockResolvedValue(
      json(
        422,
        {
          type: 'urn:x:validation',
          title: 'Invalid',
          status: 422,
          errors: [{ path: '/a', code: 'c', message: 'm' }],
        },
        { 'Content-Type': 'application/problem+json' },
      ),
    )
    const err = await unwrap(client.GET('/sites')).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).fieldErrors).toEqual({ '/a': ['m'] })
  })

  it('maps 412 to the stale error', async () => {
    fetchMock.mockResolvedValue(json(412, { title: 'stale', status: 412 }))
    const err = await unwrap(client.GET('/sites')).catch((e: unknown) => e)
    expect(isStale(err)).toBe(true)
  })

  it('turns transport failures into a network ApiError', async () => {
    fetchMock.mockRejectedValue(new TypeError('failed to fetch'))
    const err = await unwrap(client.GET('/sites')).catch((e: unknown) => e)
    expect((err as ApiError).kind).toBe('network')
  })

  it('calls the unauthorized handler for a 401 outside the sign-in flow only', async () => {
    const handler = vi.fn()
    setUnauthorizedHandler(handler)

    fetchMock.mockImplementation(() =>
      Promise.resolve(json(401, { title: 'unauthenticated', status: 401 })),
    )
    await client.GET('/sites')
    expect(handler).toHaveBeenCalledTimes(1)

    await client.POST('/auth/login', { body: { username: 'a', password: 'b' } })
    await client.GET('/auth/me')
    await client.POST('/auth/mfa', { body: { code: '123456' } })
    expect(handler).toHaveBeenCalledTimes(1)
  })
})
