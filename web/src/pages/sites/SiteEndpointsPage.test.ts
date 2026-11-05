import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok } from '@/api/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import SiteEndpointsPage from './SiteEndpointsPage.vue'
import { blog, buttonNamed, control, serve, shop } from './testing'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

async function mountList(me = adminMe) {
  serve(api, {
    '/sites': () => ok({ items: [blog, shop] }, { etag: '"v7"' }),
    '/defaults': () => ok({}),
    '/sites/{site}/effective-policy': () =>
      ok({
        site: 'shop',
        matched_endpoint: 'login',
        policy: { mode: 'detect', waf: { paranoia_level: 2, inbound_threshold: 5 } },
        sources: {
          mode: 'site',
          'waf.paranoia_level': 'endpoint:login',
          'waf.inbound_threshold': 'global',
        },
      }),
  })
  return renderWithApp(SiteEndpointsPage, { me, route: '/sites/shop/endpoints' })
}

beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

describe('SiteEndpointsPage', () => {
  it('lists endpoints most specific first with a rank and an explanation', async () => {
    const { wrapper } = await mountList()
    const rows = wrapper.findAll('tbody tr')
    expect(rows.map((r) => r.get('th').text())).toEqual(['login', 'any-login', 'api-v2', 'api'])
    expect(wrapper.findAll('[data-testid="rank"]').map((c) => c.text())).toEqual([
      '1',
      '2',
      '3',
      '4',
    ])
    expect(rows[0]?.text()).toContain('Exact path: /login')
    expect(rows[0]?.text()).toContain('POST')
    expect(rows[1]?.text()).toContain('Any')
    expect(rows[0]?.text()).toContain('1 overridden')
    expect(wrapper.get('[data-testid="precedence-help"]').text()).toContain('exact path beats')
  })

  it('tests a request: matched endpoint and every value with its source', async () => {
    const { wrapper } = await mountList()
    await control(wrapper, 'Method').setValue('POST')
    await control(wrapper, 'Path').setValue('/login')
    await wrapper
      .get('#tester-title')
      .element.closest('section')
      ?.querySelector('form')
      ?.dispatchEvent(new Event('submit', { cancelable: true }))
    await flushPromises()
    expect(api.GET).toHaveBeenCalledWith('/sites/{site}/effective-policy', {
      params: { path: { site: 'shop' }, query: { path: '/login', method: 'POST' } },
    })
    expect(wrapper.get('[data-testid="matched"]').text()).toBe('Matched endpoint: login')
    const rows = wrapper.findAll('section tbody tr').map((r) => r.text())
    expect(rows).toContainEqual(expect.stringContaining('waf.paranoia_level'))
    expect(rows.find((r) => r.includes('waf.paranoia_level'))).toContain('endpoint login')
    expect(rows.find((r) => r.includes('waf.inbound_threshold'))).toContain('global defaults')
    expect(rows.find((r) => r.startsWith('mode'))).toContain('this site')
  })

  it('hides write actions from viewers but keeps the tester', async () => {
    const { wrapper } = await mountList(viewerMe)
    expect(wrapper.text()).not.toContain('Add endpoint')
    expect(wrapper.findAll('button').some((b) => b.text() === 'Delete')).toBe(false)
    expect(wrapper.text()).toContain('Test a request')
  })

  it('deletes an endpoint with If-Match after confirmation', async () => {
    api.DELETE.mockResolvedValue(ok({}, { etag: '"v8"' }))
    const { wrapper } = await mountList()
    await buttonNamed(wrapper, 'Delete').trigger('click')
    const dialog = wrapper.get('dialog')
    expect(dialog.text()).toContain('Delete endpoint login?')
    await dialog.get('form').trigger('submit')
    await flushPromises()
    expect(api.DELETE).toHaveBeenCalledWith('/sites/{site}/endpoints/{endpoint}', {
      params: { path: { site: 'shop', endpoint: 'login' }, header: { 'If-Match': '"v7"' } },
    })
  })
})
