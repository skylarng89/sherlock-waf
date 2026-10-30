import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client, createApiClient, setUnauthorizedHandler } from '@/api/client'
import { mockClient, ok, problem } from '@/api/testing'
import { useSessionStore } from '@/stores/session'
import { adminMe, freshApp, viewerMe } from '@/test-utils'
import { installSessionExpiry, safeRedirect } from './guard'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})

const api = client as unknown as ReturnType<typeof mockClient>

/** Routes the mocked client by path so guard order does not matter. */
function server(opts: { me?: unknown; setupRequired?: boolean }) {
  api.GET.mockImplementation((path: string) => {
    if (path === '/auth/me') {
      if (opts.me === 'partial')
        return Promise.resolve(problem(403, { type: 'urn:sherlock:problem:forbidden' }))
      return Promise.resolve(opts.me ? ok(opts.me) : problem(401))
    }
    if (path === '/setup/status')
      return Promise.resolve(ok({ setup_required: opts.setupRequired ?? false }))
    return Promise.reject(new Error(`unexpected GET ${path}`))
  })
}

describe('router guard', () => {
  beforeEach(() => {
    Object.values(api).forEach((fn) => fn.mockReset())
    setUnauthorizedHandler(undefined)
  })

  it('sends anonymous users to /login with the intended route', async () => {
    server({})
    const router = freshApp()
    await router.push('/sites?x=1')
    expect(router.currentRoute.value.name).toBe('login')
    expect(router.currentRoute.value.query.redirect).toBe('/sites?x=1')
  })

  it('sends everyone to /setup while setup is required', async () => {
    server({ setupRequired: true })
    const router = freshApp()
    await router.push('/sites')
    expect(router.currentRoute.value.name).toBe('setup')
    await router.push('/login')
    expect(router.currentRoute.value.name).toBe('setup')
  })

  it('refuses /setup once setup is done', async () => {
    server({ setupRequired: false })
    const router = freshApp()
    await router.push('/setup')
    expect(router.currentRoute.value.name).toBe('login')
  })

  it('keeps a partially signed-in user on the MFA step', async () => {
    server({ me: 'partial' })
    const router = freshApp()
    await router.push('/sites')
    expect(router.currentRoute.value.name).toBe('login-mfa')
    await router.push('/login')
    expect(router.currentRoute.value.name).toBe('login-mfa')

    useSessionStore().mfaStep = 'enrol'
    await router.push('/')
    expect(router.currentRoute.value.name).toBe('login-enrol')
  })

  it('lets an authenticated user in and bounces them off the login page', async () => {
    server({ me: adminMe })
    const router = freshApp()
    await router.push('/sites')
    expect(router.currentRoute.value.name).toBe('sites')
    await router.push({ name: 'login', query: { redirect: '/audit' } })
    expect(router.currentRoute.value.fullPath).toBe('/audit')
  })

  it('shows the 403 page when a viewer opens an admin route', async () => {
    server({ me: viewerMe })
    const router = freshApp()
    await router.push('/users')
    expect(router.currentRoute.value.name).toBe('forbidden')
    expect(router.currentRoute.value.query.from).toBe('/users')
    await router.push('/sites')
    expect(router.currentRoute.value.name).toBe('sites')
  })

  it('sends a 401 mid-session to /login with an expiry notice and a return path', async () => {
    server({ me: adminMe })
    const router = freshApp()
    installSessionExpiry(router)
    await router.push('/certificates')
    server({})

    // A real client whose server answers 401 drives the same middleware the app uses.
    const live = createApiClient({
      baseUrl: 'http://localhost/api/v1',
      fetch: () => Promise.resolve(new Response('{}', { status: 401 })),
    })
    await live.GET('/sites')
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('login'))
    expect(router.currentRoute.value.query).toMatchObject({
      expired: '1',
      redirect: '/certificates',
    })
    expect(useSessionStore().status).toBe('anonymous')
  })
})

describe('safeRedirect', () => {
  it.each([
    ['/sites', '/sites'],
    ['/sites?a=1', '/sites?a=1'],
    ['//evil.example', undefined],
    ['https://evil.example', undefined],
    ['/\\evil.example', undefined],
    ['/login', undefined],
    ['/setup', undefined],
    [undefined, undefined],
    [['/a'], undefined],
  ])('%s -> %s', (input, expected) => expect(safeRedirect(input)).toBe(expected))
})
