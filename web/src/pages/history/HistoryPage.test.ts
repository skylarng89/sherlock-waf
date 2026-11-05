import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp } from '@/test-utils'
import HistoryPage from './HistoryPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

const v = (id: string, extra: Record<string, unknown> = {}) => ({
  id,
  parent_id: '',
  created_at: '2026-10-01T10:00:00Z',
  author_type: 'user',
  author_id: 'ada',
  source: 'api',
  schema_version: 1,
  applied: true,
  diff: {
    global: false,
    sites: { added: ['shop'], removed: [], changed: [{ site: 'blog', fields: ['mode'] }] },
  },
  ...extra,
})

function route(responses: Record<string, unknown>) {
  api.GET.mockImplementation(
    async (path: string, init?: { params?: { query?: { cursor?: string } } }) => {
      if (path === '/config') return ok({}, { etag: '"V2"' })
      const key = init?.params?.query?.cursor ? `versions:${init.params.query.cursor}` : 'versions'
      return responses[key] ?? problem(500)
    },
  )
}

beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

describe('HistoryPage', () => {
  it('lists versions with author, source, applied flag, summary and marks the live one', async () => {
    route({
      versions: ok({ items: [v('V2'), v('V1', { applied: false, source: 'rollback', diff: {} })] }),
    })
    const { wrapper } = await renderWithApp(HistoryPage, { me: adminMe })
    const rows = wrapper.findAll('tbody tr')
    expect(rows).toHaveLength(2)
    expect(rows[0]?.text()).toContain('user ada')
    expect(rows[0]?.text()).toContain('API')
    expect(rows[0]?.text()).toContain('1 site added, 1 site changed')
    expect(rows[0]?.text()).toContain('Current')
    expect(rows[1]?.text()).not.toContain('Current')
    expect(rows[1]?.text()).toContain('Not applied')
    expect(rows[1]?.text()).toContain('Rollback')
    expect(rows[1]?.text()).toContain('No changes recorded')
    expect(wrapper.get('a[aria-label="View version V1"]').attributes('href')).toBe('/history/V1')
  })

  it('paginates with next_cursor', async () => {
    route({
      versions: ok({ items: [v('V3')], next_cursor: 'c1' }),
      'versions:c1': ok({ items: [v('V2')] }),
    })
    const { wrapper } = await renderWithApp(HistoryPage, { me: adminMe })
    const more = wrapper.findAll('button').find((b) => b.text() === 'Load more versions')
    expect(more).toBeDefined()
    await more?.trigger('click')
    await flushPromises()
    expect(wrapper.findAll('tbody tr')).toHaveLength(2)
    expect(api.GET).toHaveBeenCalledWith(
      '/config/versions',
      expect.objectContaining({ params: { query: { limit: 50, cursor: 'c1' } } }),
    )
    expect(wrapper.text()).not.toContain('Load more versions')
  })

  it('shows an empty state', async () => {
    route({ versions: ok({ items: [] }) })
    const { wrapper } = await renderWithApp(HistoryPage, { me: adminMe })
    expect(wrapper.text()).toContain('No versions yet')
  })

  it('shows an alert on error', async () => {
    route({})
    const { wrapper } = await renderWithApp(HistoryPage, { me: adminMe })
    expect(wrapper.get('[role="alert"]').text()).toContain('could not be loaded')
  })

  it('compares two versions side by side', async () => {
    route({ versions: ok({ items: [v('V2'), v('V1')] }) })
    const snap = (sites: unknown[]) => ok({ ...v('x'), snapshot: { schema_version: 1, sites } })
    const site = (id: string, mode: string) => ({
      id,
      hosts: [`${id}.test`],
      upstreams: {},
      policy: { mode },
    })
    const original = api.GET.getMockImplementation()
    api.GET.mockImplementation(
      async (path: string, init?: { params?: { path?: { id?: string } } }) => {
        if (path === '/config/versions/{id}') {
          return init?.params?.path?.id === 'V1'
            ? snap([site('a', 'detect')])
            : snap([site('a', 'block'), site('b', 'off')])
        }
        return original?.(path, init)
      },
    )
    const { wrapper } = await renderWithApp(HistoryPage, { me: adminMe })
    await wrapper.get('#cmp-left').setValue('V1')
    await wrapper.get('#cmp-right').setValue('V2')
    await wrapper
      .findAll('button')
      .find((b) => b.text() === 'Compare')
      ?.trigger('click')
    await flushPromises()
    const text = wrapper.findAll('table')[1]?.text() ?? ''
    expect(text).toContain('a.test (detect)')
    expect(text).toContain('a.test (block)')
    expect(text).toContain('Not present')
  })
})
