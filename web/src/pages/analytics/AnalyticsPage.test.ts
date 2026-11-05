import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'

import AnalyticsPage from './AnalyticsPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>
beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

vi.mock('vue-echarts', async () => {
  const { defineComponent, h } = await import('vue')
  return {
    default: defineComponent({
      name: 'VChartStub',
      props: { option: { type: Object, required: true }, autoresize: Boolean },
      setup: () => () => h('div', { 'data-testid': 'chart' }),
    }),
  }
})
const top = (dim: string) => ({
  dim,
  from: '',
  to: '',
  sampled: dim === 'ip',
  items: [
    { value: `${dim}-a`, count: 30 },
    { value: `${dim}-b`, count: 5 },
  ],
})

function serve() {
  api.GET.mockImplementation(
    async (path: string, init?: { params?: { query?: { dim?: string } } }) => {
      if (path === '/sites') return ok({ items: [{ id: 'shop' }] })
      if (path === '/stats/timeseries') {
        return ok({
          from: '',
          to: '',
          step: '5m',
          points: [{ t: '2026-10-29T10:00:00Z', counts: { allow: 5, block: 2, challenge: 1 } }],
        })
      }
      if (path === '/stats/top') return ok(top(init?.params?.query?.dim ?? ''))
      return problem(404)
    },
  )
}

describe('analytics', () => {
  it('loads the series and one panel per dimension', async () => {
    serve()
    const { wrapper } = await renderWithApp(AnalyticsPage, { me: viewerMe, route: '/analytics' })
    const dims = api.GET.mock.calls
      .filter((c) => c[0] === '/stats/top')
      .map((c) => (c[1] as { params: { query: { dim: string } } }).params.query.dim)
    expect(dims.sort()).toEqual(['country', 'ip', 'path', 'rule', 'site'])
    expect(wrapper.findAll('[data-testid="chart"]')).toHaveLength(6)
    expect(wrapper.get('[data-testid="top-ip"]').text()).toContain('approximate')
  })

  it('offers a table with the same numbers for every chart', async () => {
    serve()
    const { wrapper } = await renderWithApp(AnalyticsPage, { me: adminMe, route: '/analytics' })
    const toggle = wrapper
      .get('[data-testid="top-rule"]')
      .findAll('button')
      .find((b) => b.text().includes('View as table'))
    await toggle?.trigger('click')
    const table = wrapper.get('[data-testid="top-rule"] table')
    expect(table.text()).toContain('rule-a')
    expect(table.text()).toContain('30')
    expect(table.find('caption').exists()).toBe(true)

    const series = wrapper
      .get('[data-testid="series-panel"]')
      .findAll('button')
      .find((b) => b.text().includes('View as table'))
    await series?.trigger('click')
    expect(wrapper.get('[data-testid="series-panel"] table').text()).toContain('8')
  })

  it('narrows the panels to one site', async () => {
    serve()
    const { wrapper } = await renderWithApp(AnalyticsPage, { me: adminMe, route: '/analytics' })
    const label = wrapper.findAll('label').find((l) => l.text() === 'Site')
    await wrapper.get(`[id="${label?.attributes('for')}"]`).setValue('shop')
    await flushPromises()
    const rule = api.GET.mock.calls
      .filter((c) => c[0] === '/stats/top')
      .map((c) => (c[1] as { params: { query: { dim: string; site?: string } } }).params.query)
    expect(
      rule
        .filter((q) => q.site === 'shop')
        .map((q) => q.dim)
        .sort(),
    ).toEqual(['country', 'ip', 'path', 'rule'])
  })

  it('reports a failing panel without breaking the others', async () => {
    api.GET.mockImplementation(async (path: string) =>
      path === '/stats/top' ? problem(500) : ok({ items: [], points: [], step: '5m' }),
    )
    const { wrapper } = await renderWithApp(AnalyticsPage, { me: adminMe, route: '/analytics' })
    expect(wrapper.findAll('[role="alert"]').length).toBe(5)
  })
})
