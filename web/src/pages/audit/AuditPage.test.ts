import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import { mockClient, ok, problem } from '@/api/testing'
import { adminMe, renderWithApp } from '@/test-utils'
import AuditPage from './AuditPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

const entry = (seq: number, extra: Record<string, unknown> = {}) => ({
  seq,
  id: `id-${seq}`,
  at: '2026-01-01T00:00:00Z',
  actor_type: 'user',
  actor_id: 'u1',
  action: 'user.create',
  hash: `hash-${seq}`,
  ...extra,
})

function mockApi(pages: Record<string, unknown>) {
  api.GET.mockImplementation(
    async (path: string, init?: { params?: { query?: { before_seq?: number } } }) => {
      if (path === '/system/info') {
        return ok({ audit_head: { seq: 3, hash: 'headhash' }, version: 'x' })
      }
      const before = init?.params?.query?.before_seq
      return ok(pages[String(before)] ?? pages.first)
    },
  )
}

beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

describe('AuditPage', () => {
  it('shows entries, the chain head and its help text', async () => {
    mockApi({ first: { items: [entry(3), entry(2)] } })
    const { wrapper } = await renderWithApp(AuditPage, { me: adminMe })
    expect(wrapper.get('[data-testid="audit-3"]').text()).toContain('user.create')
    expect(wrapper.get('[data-testid="head-seq"]').text()).toBe('3')
    expect(wrapper.get('[data-testid="head-hash"]').text()).toBe('headhash')
    expect(wrapper.text()).toContain('sherlock audit verify')
    expect(wrapper.text()).toContain('reached the start')
  })

  it('paginates with before_seq and appends older entries', async () => {
    mockApi({
      first: { items: [entry(3), entry(2)], next_before_seq: 2 },
      '2': { items: [entry(1)] },
    })
    const { wrapper } = await renderWithApp(AuditPage, { me: adminMe })
    const button = wrapper.findAll('button').find((b) => b.text() === 'Load older entries')
    await button?.trigger('click')
    await flushPromises()
    expect(api.GET).toHaveBeenCalledWith('/audit', {
      params: { query: { limit: 50, before_seq: 2 } },
    })
    expect(wrapper.find('[data-testid="audit-1"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('reached the start')
  })

  it('filters loaded entries client-side and says so', async () => {
    mockApi({
      first: {
        items: [entry(3, { action: 'login.ok', actor_type: 'token' }), entry(2)],
      },
    })
    const { wrapper } = await renderWithApp(AuditPage, { me: adminMe })
    expect(wrapper.text()).toContain('apply only to the entries already loaded')
    await wrapper.get('input[name="action"]').setValue('login')
    expect(wrapper.find('[data-testid="audit-3"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="audit-2"]').exists()).toBe(false)
    await wrapper.get('input[name="action"]').setValue('')
    await wrapper.get('select[name="actor_type"]').setValue('user')
    expect(wrapper.find('[data-testid="audit-3"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="audit-2"]').exists()).toBe(true)
  })

  it('shows details as escaped text, with seq and hash visible', async () => {
    mockApi({
      first: { items: [entry(3, { details: { note: '<img src=x onerror=alert(1)>' } })] },
    })
    const { wrapper } = await renderWithApp(AuditPage, { me: adminMe })
    await wrapper.get('button[aria-label="Show details of entry 3"]').trigger('click')
    expect(wrapper.find('pre img').exists()).toBe(false)
    expect(wrapper.get('pre').text()).toContain('<img src=x onerror=alert(1)>')
    expect(wrapper.text()).toContain('hash-3')
    expect(wrapper.find('button[aria-expanded="true"]').exists()).toBe(true)
  })

  it('shows empty and error states', async () => {
    mockApi({ first: { items: [] } })
    const empty = await renderWithApp(AuditPage, { me: adminMe })
    expect(empty.wrapper.text()).toContain('No audit entries')
    api.GET.mockReset()
    api.GET.mockResolvedValue(problem(500, { detail: 'boom' }))
    const failed = await renderWithApp(AuditPage, { me: adminMe })
    expect(failed.wrapper.find('[role="alert"]').text()).toContain('boom')
  })
})
