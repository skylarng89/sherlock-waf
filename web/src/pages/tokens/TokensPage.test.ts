import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import { mockClient, ok, problem } from '@/api/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import TokensPage from './TokensPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

const token = (id: string, userId: string, extra: Record<string, unknown> = {}) => ({
  id,
  user_id: userId,
  name: `tok-${id}`,
  scopes: ['read'],
  cidrs: [],
  expires_at: null,
  last_used_at: null,
  created_at: '2026-01-01T00:00:00Z',
  ...extra,
})

beforeEach(() => {
  Object.values(api).forEach((fn) => fn.mockReset())
  api.GET.mockResolvedValue(ok({ items: [token('t1', 'u1'), token('t2', 'u9')] }))
})

describe('TokensPage', () => {
  it('shows the owner column to admins only', async () => {
    const admin = await renderWithApp(TokensPage, { me: adminMe })
    expect(admin.wrapper.text()).toContain('Owner')
    expect(admin.wrapper.text()).toContain('u9')
    const viewer = await renderWithApp(TokensPage, { me: viewerMe })
    expect(viewer.wrapper.text()).not.toContain('Owner')
  })

  it('shows empty and error states', async () => {
    api.GET.mockResolvedValueOnce(ok({ items: [] }))
    const empty = await renderWithApp(TokensPage, { me: adminMe })
    expect(empty.wrapper.text()).toContain('No API tokens')
    api.GET.mockResolvedValueOnce(problem(500, { detail: 'boom' }))
    const failed = await renderWithApp(TokensPage, { me: adminMe })
    expect(failed.wrapper.find('[role="alert"]').text()).toContain('boom')
  })

  it('creates a token, shows the secret once and clears it on dismissal', async () => {
    api.POST.mockResolvedValueOnce(
      ok(
        {
          ...token('t3', 'u1', { name: 'ci', scopes: ['read', 'events:read'] }),
          token: 'shk_t3_SECRET',
        },
        { status: 201 },
      ),
    )
    const { wrapper } = await renderWithApp(TokensPage, { me: adminMe })
    await wrapper.get('input[name="name"]').setValue('ci')
    await wrapper.get('input[value="read"]').setValue(true)
    await wrapper.get('input[value="events:read"]').setValue(true)
    await wrapper.get('textarea[name="cidrs"]').setValue('203.0.113.0/24, 10.0.0.0/8')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api.POST).toHaveBeenCalledWith('/tokens', {
      body: {
        name: 'ci',
        scopes: ['read', 'events:read'],
        cidrs: ['203.0.113.0/24', '10.0.0.0/8'],
      },
    })
    expect(wrapper.get('[data-testid="secret-value"]').text()).toBe('shk_t3_SECRET')
    expect(wrapper.text()).toContain('You will not see this token again')

    await wrapper
      .findAll('dialog button')
      .find((b) => b.text() === 'Close')
      ?.trigger('click')
    await flushPromises()
    expect(wrapper.html()).not.toContain('SECRET')
  })

  it('requires a scope and maps server errors to fields', async () => {
    const { wrapper } = await renderWithApp(TokensPage, { me: adminMe })
    await wrapper.get('input[name="name"]').setValue('ci')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api.POST).not.toHaveBeenCalled()
    expect(wrapper.get('#token-scopes-error').text()).toContain('Choose at least one scope')

    api.POST.mockResolvedValueOnce(
      problem(400, { errors: [{ path: '/cidrs/0', code: 'cidr', message: 'invalid CIDR' }] }),
    )
    await wrapper.get('input[value="read"]').setValue(true)
    await wrapper.get('textarea[name="cidrs"]').setValue('nope')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    const area = wrapper.get('textarea[name="cidrs"]')
    expect(area.attributes('aria-invalid')).toBe('true')
    expect(wrapper.get(`#${area.attributes('id')}-error`).text()).toContain('invalid CIDR')
  })

  it('revokes after confirmation', async () => {
    api.DELETE.mockResolvedValueOnce(ok(null, { status: 204 }))
    const { wrapper } = await renderWithApp(TokensPage, { me: adminMe })
    await wrapper.get('button[aria-label="Revoke token tok-t1"]').trigger('click')
    await flushPromises()
    await wrapper
      .findAll('dialog button')
      .find((b) => b.text() === 'Revoke token')
      ?.trigger('click')
    await flushPromises()
    expect(api.DELETE).toHaveBeenCalledWith('/tokens/{id}', { params: { path: { id: 't1' } } })
  })
})
