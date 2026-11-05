import { flushPromises } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import VChart from 'vue-echarts'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { useThemeStore } from '@/stores/theme'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import OverviewPage from './OverviewPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
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
const api = client as unknown as ReturnType<typeof mockClient>

const sites = {
  items: [
    { id: 'shop', hosts: ['shop.test'], upstreams: {}, policy: { mode: 'block' } },
    { id: 'blog', hosts: ['blog.test'], upstreams: {}, policy: { mode: 'detect' } },
    { id: 'api', hosts: ['api.test'], upstreams: {}, policy: { mode: 'block' } },
    { id: 'misc', hosts: ['m.test'], upstreams: {} },
  ],
}
const info = {
  version: '0.4.0',
  crs_version: '4.8.0',
  database: 'sqlite',
  features: [],
  ready: true,
  config_version: 'V9',
}
const series = {
  from: '',
  to: '',
  step: '1m',
  points: [
    { t: '2026-10-01T10:00:00Z', counts: { allow: 5, block: 2 } },
    { t: '2026-10-01T10:01:00Z', counts: { allow: 3, ratelimit: 1 } },
  ],
}

let seriesResponse: unknown
function setup() {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/sites') return ok(sites)
    if (path === '/system/info') return ok(info)
    if (path === '/stats/timeseries') return seriesResponse
    return problem(404)
  })
}
const timeseriesCalls = () =>
  api.GET.mock.calls.filter((c) => c[0] === '/stats/timeseries') as [
    string,
    { params: { query: Record<string, string> } },
  ][]

function stubMotion(reduce: boolean) {
  window.matchMedia = ((q: string) => ({
    matches: q.includes('reduced-motion') ? reduce : false,
    addEventListener: () => {},
    removeEventListener: () => {},
  })) as unknown as typeof window.matchMedia
}

beforeEach(() => {
  Object.values(api).forEach((fn) => fn.mockReset())
  seriesResponse = ok(series)
  stubMotion(false)
  setup()
})
afterEach(() => vi.useRealTimers())

describe('OverviewPage', () => {
  it('shows site, CRS, version, database, ready and config version cards', async () => {
    const { wrapper } = await renderWithApp(OverviewPage, { me: adminMe })
    expect(wrapper.get('[data-testid="sites-total"]').text()).toBe('4 sites')
    expect(wrapper.text()).toContain('Block: 2')
    expect(wrapper.text()).toContain('Detect: 1')
    expect(wrapper.text()).toContain('Off: 0')
    expect(wrapper.text()).toContain('Inherited: 1')
    expect(wrapper.get('[data-testid="crs-version"]').text()).toBe('4.8.0')
    expect(wrapper.get('[data-testid="sherlock-version"]').text()).toBe('0.4.0')
    expect(wrapper.get('[data-testid="database"]').text()).toBe('sqlite')
    expect(wrapper.get('[data-testid="config-version"]').text()).toBe('V9')
    expect(wrapper.text()).toContain('Ready')
  })

  it('builds the chart option: one series per action, distinct styles, labelled', async () => {
    const { wrapper } = await renderWithApp(OverviewPage, { me: adminMe })
    const chart = wrapper.findComponent(VChart)
    expect(chart.attributes('aria-label')).toContain('Line chart of requests by action')
    const option = chart.props('option') as {
      series: { name: string; data: number[] }[]
      legend: unknown
    }
    expect(option.series.map((s) => s.name)).toEqual(['Allow', 'Block', 'Rate limit'])
    expect(option.series[0]?.data).toEqual([5, 3])
    expect(option.legend).toBeDefined()
  })

  it('requests the selected range with the right step and site', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] })
    vi.setSystemTime(new Date('2026-10-01T10:00:30Z'))
    const { wrapper } = await renderWithApp(OverviewPage, { me: adminMe })
    expect(timeseriesCalls()[0]?.[1].params.query).toEqual({
      from: '2026-10-01T09:00:00.000Z',
      to: '2026-10-01T10:00:00.000Z',
      step: '1m',
    })
    await wrapper.get('#ov-range').setValue('7d')
    await flushPromises()
    await wrapper.get('#ov-site').setValue('shop')
    await flushPromises()
    const last = timeseriesCalls().at(-1)?.[1].params.query
    expect(last).toEqual({
      from: '2026-09-24T10:00:00.000Z',
      to: '2026-10-01T10:00:00.000Z',
      step: '1h',
      site: 'shop',
    })
  })

  it('table alternative equals the chart data', async () => {
    const { wrapper } = await renderWithApp(OverviewPage, { me: adminMe })
    const toggle = wrapper.findAll('button').find((b) => b.text() === 'View as table')
    await toggle?.trigger('click')
    expect(wrapper.findComponent(VChart).exists()).toBe(false)
    const rows = wrapper.findAll('tbody tr').map((r) =>
      r
        .findAll('th,td')
        .slice(1)
        .map((c) => c.text()),
    )
    expect(rows).toEqual([
      ['5', '2', '0', '7'],
      ['3', '0', '1', '4'],
    ])
    const headers = wrapper.findAll('thead th').map((h) => h.text())
    expect(headers.slice(1)).toEqual(['Allow', 'Block', 'Rate limit', 'Total'])
  })

  it('explains the empty state when there is no traffic', async () => {
    seriesResponse = ok({ ...series, points: [{ t: '2026-10-01T10:00:00Z', counts: {} }] })
    const { wrapper } = await renderWithApp(OverviewPage, { me: adminMe })
    expect(wrapper.text()).toContain('Events appear here once traffic flows')
    expect(wrapper.findComponent(VChart).exists()).toBe(false)
  })

  it('shows an alert when the series fails', async () => {
    seriesResponse = problem(500)
    const { wrapper } = await renderWithApp(OverviewPage, { me: adminMe })
    expect(wrapper.text()).toContain('chart data could not be loaded')
    expect(wrapper.find('[role="alert"]').exists()).toBe(true)
  })

  it('refreshes every 30 seconds until paused', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] })
    const { wrapper } = await renderWithApp(OverviewPage, { me: adminMe })
    expect(timeseriesCalls()).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(30_000)
    expect(timeseriesCalls()).toHaveLength(2)
    await wrapper
      .findAll('button')
      .find((b) => b.text() === 'Pause auto-refresh')
      ?.trigger('click')
    expect(wrapper.text()).toContain('Auto-refresh paused')
    await vi.advanceTimersByTimeAsync(90_000)
    expect(timeseriesCalls()).toHaveLength(2)
    await wrapper
      .findAll('button')
      .find((b) => b.text() === 'Resume auto-refresh')
      ?.trigger('click')
    await flushPromises()
    expect(timeseriesCalls()).toHaveLength(3)
  })

  it('disables chart animation under prefers-reduced-motion', async () => {
    stubMotion(true)
    const { wrapper } = await renderWithApp(OverviewPage, { me: adminMe })
    expect(
      (wrapper.findComponent(VChart).props('option') as { animation: boolean }).animation,
    ).toBe(false)
  })

  it('re-renders with other colours when the theme changes', async () => {
    const { wrapper } = await renderWithApp(OverviewPage, { me: adminMe })
    const colour = () =>
      (wrapper.findComponent(VChart).props('option') as { series: { color: string }[] }).series[0]
        ?.color
    useThemeStore().setPreference('light')
    await flushPromises()
    const light = colour()
    useThemeStore().setPreference('dark')
    await flushPromises()
    expect(colour()).not.toBe(light)
  })

  it('viewers see the chart but not system info', async () => {
    const { wrapper } = await renderWithApp(OverviewPage, { me: viewerMe })
    expect(wrapper.findComponent(VChart).exists()).toBe(true)
    expect(wrapper.find('[data-testid="crs-version"]').exists()).toBe(false)
    expect(api.GET).not.toHaveBeenCalledWith('/system/info', expect.anything())
  })

  it('users without events:read get a reduced page without the chart', async () => {
    const { wrapper } = await renderWithApp(OverviewPage, {
      me: { ...viewerMe, permissions: ['config:read'] },
    })
    expect(wrapper.findComponent(VChart).exists()).toBe(false)
    expect(wrapper.text()).toContain('Traffic charts are not available')
    expect(timeseriesCalls()).toHaveLength(0)
  })
})
