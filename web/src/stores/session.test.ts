import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import { mockClient, ok, problem } from '@/api/testing'
import { adminMe, viewerMe } from '@/test-utils'
import { useSessionStore } from './session'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})

const api = client as unknown as ReturnType<typeof mockClient>

describe('session store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    Object.values(api).forEach((fn) => fn.mockReset())
  })

  it('fetchMe signs in on 200, is anonymous on 401 and partial on 403', async () => {
    const session = useSessionStore()
    api.GET.mockResolvedValueOnce(ok(adminMe))
    expect(await session.fetchMe()).toBe('authenticated')
    expect(session.me?.username).toBe('ada')

    api.GET.mockResolvedValueOnce(problem(401))
    expect(await session.fetchMe()).toBe('anonymous')
    expect(session.me).toBeNull()

    api.GET.mockResolvedValueOnce(problem(403, { type: 'urn:sherlock:problem:forbidden' }))
    expect(await session.fetchMe()).toBe('partial')
  })

  it('treats a transport failure as signed out', async () => {
    api.GET.mockRejectedValueOnce(new TypeError('offline'))
    expect(await useSessionStore().fetchMe()).toBe('anonymous')
  })

  it('login records which MFA step is next', async () => {
    const session = useSessionStore()
    api.POST.mockResolvedValueOnce(ok({ status: 'mfa_enrol_required' }))
    expect(await session.login('a', 'b')).toBe('mfa_enrol_required')
    expect(session.status).toBe('partial')
    expect(session.mfaStep).toBe('enrol')

    api.POST.mockResolvedValueOnce(ok({ status: 'mfa_required' }))
    await session.login('a', 'b')
    expect(session.mfaStep).toBe('verify')
  })

  it('verifyMfa completes the session', async () => {
    const session = useSessionStore()
    api.POST.mockResolvedValueOnce(ok(viewerMe))
    await session.verifyMfa('123456')
    expect(session.isAuthenticated).toBe(true)
    expect(api.POST).toHaveBeenCalledWith('/auth/mfa', { body: { code: '123456' } })
  })

  it('can() checks permissions and treats none as allowed', () => {
    const session = useSessionStore()
    session.setMe(viewerMe)
    expect(session.can('config:read')).toBe(true)
    expect(session.can('users:manage')).toBe(false)
    expect(session.can(undefined)).toBe(true)
  })

  it('logout clears the session even when the server call fails', async () => {
    const session = useSessionStore()
    session.setMe(adminMe)
    api.POST.mockRejectedValueOnce(new TypeError('offline'))
    await session.logout()
    expect(session.status).toBe('anonymous')
    expect(session.me).toBeNull()
  })

  it('reads setup status, defaulting to not required on failure', async () => {
    const session = useSessionStore()
    api.GET.mockResolvedValueOnce(ok({ setup_required: true }))
    expect(await session.fetchSetupStatus()).toBe(true)
    session.markSetupComplete()
    expect(session.setupRequired).toBe(false)
    api.GET.mockResolvedValueOnce(problem(500))
    expect(await session.fetchSetupStatus()).toBe(false)
  })
})
