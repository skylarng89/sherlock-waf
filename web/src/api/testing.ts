// Test helpers for mocking the API client in Vitest. Import only from *.test.ts.
import { vi } from 'vitest'

interface Raw {
  data?: unknown
  error?: unknown
  response: Response
}

/** A successful openapi-fetch result: `client.GET.mockResolvedValue(ok({...}, { etag: '"v1"' }))`. */
export function ok(data: unknown, init: { status?: number; etag?: string } = {}): Raw {
  const headers = new Headers()
  if (init.etag) headers.set('ETag', init.etag)
  return { data, response: new Response(null, { status: init.status ?? 200, headers }) }
}

/** An RFC 9457 failure result. `body` fields are merged over `{ type, title, status }`. */
export function problem(
  status: number,
  body: Record<string, unknown> = {},
  headers: Record<string, string> = {},
): Raw {
  return {
    error: { type: 'about:blank', title: `HTTP ${status}`, status, ...body },
    response: new Response(null, { status, headers }),
  }
}

/** A client double: assign it via `vi.mock('@/api/client', ...)`, see docs/engineering/dashboard.md. */
export function mockClient() {
  return {
    GET: vi.fn(),
    POST: vi.fn(),
    PUT: vi.fn(),
    PATCH: vi.fn(),
    DELETE: vi.fn(),
  }
}
