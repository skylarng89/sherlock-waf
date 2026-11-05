import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'

import WouldBlockPage from './WouldBlockPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>
beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

const sites = {
  items: [
    { id: 'blog', policy: { mode: 'block' } },
    { id: 'shop', name: 'Shop', policy: { mode: 'detect' } },
  ],
}
const report = {
  site: 'shop',
  from: '',
  to: '',
  total: 3,
  truncated: false,
  by_rule: [{ rule_id: '942100', count: 3 }],
  by_path: [
    { path: '/search', count: 2 },
    { path: '/login', count: 1 },
  ],
  requests: [
    {
      event_id: 'e1',
      ts: '2026-10-29T11:00:00Z',
      client_ip: '203.0.113.7',
      method: 'GET',
      path: '/search',
      rule_ids: ['942100'],
    },
  ],
}

function serve(rep: unknown = report) {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/sites') return ok(sites, { etag: '"v5"' })
    if (path === '/reports/would-block') return ok(rep)
    if (path === '/reports/would-block.csv') return ok(new Blob(['a,b\n']))
    return problem(404)
  })
}
const button = (
  w: { findAll(s: string): { text(): string; trigger(e: string): Promise<void> }[] },
  n: string,
) => w.findAll('button').find((b) => b.text().includes(n))

describe('would-block report', () => {
  it('defaults to a detect-mode site and lists rules, paths and requests', async () => {
    serve()
    const { wrapper, router } = await renderWithApp(WouldBlockPage, {
      me: adminMe,
      route: '/reports/would-block',
    })
    await flushPromises()
    expect(router.currentRoute.value.query.site).toBe('shop')
    const q = (
      api.GET.mock.calls.find((c) => c[0] === '/reports/would-block')?.[1] as {
        params: { query: Record<string, string> }
      }
    ).params.query
    expect(q.site).toBe('shop')
    expect(wrapper.get('[data-testid="wb-total-count"]').text()).toBe('3')
    expect(wrapper.get('[data-testid="by-rule"]').text()).toContain('942100')
    expect(wrapper.get('[data-testid="by-path"]').text()).toContain('/search')
    expect(wrapper.get('[data-testid="wb-requests"] a').attributes('href')).toBe('/events/e1')
  })

  it('exports the CSV through the typed client', async () => {
    serve()
    URL.createObjectURL = vi.fn(() => 'blob:x')
    URL.revokeObjectURL = vi.fn()
    const { wrapper } = await renderWithApp(WouldBlockPage, {
      me: adminMe,
      route: '/reports/would-block?site=shop',
    })
    await button(wrapper, 'Export CSV')?.trigger('click')
    await flushPromises()
    const call = api.GET.mock.calls.find((c) => c[0] === '/reports/would-block.csv')
    expect((call?.[1] as { parseAs: string }).parseAs).toBe('blob')
    expect(URL.createObjectURL).toHaveBeenCalled()
  })

  it('switches the site to block after confirmation', async () => {
    serve()
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v6"' }))
    const { wrapper } = await renderWithApp(WouldBlockPage, {
      me: adminMe,
      route: '/reports/would-block?site=shop',
    })
    await button(wrapper, 'Switch to block mode')?.trigger('click')
    expect(api.PATCH).not.toHaveBeenCalled()
    const dialog = wrapper.findAll('dialog').find((d) => d.text().includes('block'))
    await button(dialog as never, 'Switch to block')?.trigger('click')
    await flushPromises()
    const [path, init] = api.PATCH.mock.calls[0] as [string, { params: unknown; body: unknown }]
    expect(path).toBe('/sites/{site}')
    expect(init.params).toEqual({ path: { site: 'shop' }, header: { 'If-Match': '"v5"' } })
    expect(init.body).toEqual({ policy: { mode: 'block' } })
  })

  it('hides the switch for a viewer and for a site already in block mode', async () => {
    serve()
    const viewer = await renderWithApp(WouldBlockPage, {
      me: viewerMe,
      route: '/reports/would-block?site=shop',
    })
    expect(button(viewer.wrapper, 'Switch to block mode')).toBeUndefined()
    viewer.wrapper.unmount()
    const blocked = await renderWithApp(WouldBlockPage, {
      me: adminMe,
      route: '/reports/would-block?site=blog',
    })
    expect(button(blocked.wrapper, 'Switch to block mode')).toBeUndefined()
    expect(blocked.wrapper.text()).toContain('not in detect mode')
  })

  it('shows a clean state and a truncation warning', async () => {
    serve({ ...report, total: 0, by_rule: [], by_path: [], requests: [], truncated: true })
    const { wrapper } = await renderWithApp(WouldBlockPage, {
      me: adminMe,
      route: '/reports/would-block?site=shop',
    })
    expect(wrapper.text()).toContain('Nothing would have been blocked')
    expect(wrapper.text()).toContain('lower bound')
  })
})
