import { request as httpRequest } from 'node:http'
import { request, type APIRequestContext, type APIResponse } from '@playwright/test'

const SESSION_COOKIE = '__Host-sherlock_session'
const CSRF_COOKIE = '__Host-sherlock_csrf'

export { SESSION_COOKIE, CSRF_COOKIE }

/** Minimal authenticated client for the control-plane API, used for setup and assertions. */
export class ApiClient {
  private constructor(
    readonly ctx: APIRequestContext,
    readonly baseURL: string,
  ) {}

  static async create(baseURL: string, storageState?: string): Promise<ApiClient> {
    const ctx = await request.newContext({ baseURL, ignoreHTTPSErrors: true, storageState })
    return new ApiClient(ctx, baseURL)
  }

  async csrf(): Promise<string> {
    const { cookies } = await this.ctx.storageState()
    return cookies.find((c) => c.name === CSRF_COOKIE)?.value ?? ''
  }

  private async headers(): Promise<Record<string, string>> {
    return { 'X-CSRF-Token': await this.csrf() }
  }

  async get(path: string): Promise<APIResponse> {
    return this.ctx.get(`/api/v1${path}`)
  }

  async post(path: string, data?: unknown): Promise<APIResponse> {
    return this.ctx.post(`/api/v1${path}`, { data, headers: await this.headers() })
  }

  async json<T>(res: APIResponse, expected = 200): Promise<T> {
    if (res.status() !== expected) {
      throw new Error(`${res.url()} answered ${res.status()}: ${await res.text()}`)
    }
    return (await res.json()) as T
  }

  async storageState(path: string): Promise<void> {
    await this.ctx.storageState({ path })
  }

  async dispose(): Promise<void> {
    await this.ctx.dispose()
  }
}

/** Sends a plain HTTP request to the data plane; the Host header selects the site. */
export function dataPlaneGet(
  httpPort: number,
  host: string,
  path: string,
): Promise<{ status: number; body: string; headers: Record<string, string> }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port: httpPort,
        path,
        method: 'GET',
        headers: { Host: host },
        agent: false,
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (chunk: Buffer) => chunks.push(chunk))
        res.on('end', () => {
          const headers: Record<string, string> = {}
          for (const [key, value] of Object.entries(res.headers)) {
            headers[key] = Array.isArray(value) ? value.join(', ') : (value ?? '')
          }
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf8'),
            headers,
          })
        })
      },
    )
    req.setTimeout(10_000, () => req.destroy(new Error(`data plane request timed out: ${path}`)))
    req.on('error', reject)
    req.end()
  })
}
