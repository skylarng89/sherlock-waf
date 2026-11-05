import { flushPromises } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp } from '@/test-utils'

import EventsPage from './EventsPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>
beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

const ev = (id: string, extra: object = {}) => ({
  id,
  ts: '2026-10-29T11:00:00Z',
  site_id: 'shop',
  action: 'block',
  request: { method: 'GET', path: `/p/${id}` },
  client: { ip: '203.0.113.7', country: 'DE' },
  response: { status: 403 },
  findings: [{ rule_id: '942100' }],
  ...extra,
})

function serve(pages: Record<string, unknown> | ((q: Record<string, unknown>) => unknown)) {
  api.GET.mockImplementation(async (path: string, init?: { params?: { query?: object } }) => {
    if (path === '/sites') return ok({ items: [{ id: 'shop' }, { id: 'blog' }] })
    if (path === '/events') {
      const q = (init?.params?.query ?? {}) as Record<string, unknown>
      return ok(typeof pages === 'function' ? pages(q) : pages)
    }
    return problem(404)
  })
}
const eventCalls = () =>
  api.GET.mock.calls.filter((c) => c[0] === '/events') as [
    string,
    { params: { query: Record<string, unknown> } },
  ][]

afterEach(() => vi.useRealTimers())

describe('attack explorer', () => {
  it('lists events and links each to its detail page', async () => {
    serve({ items: [ev('e1'), ev('e2')] })
    const { wrapper } = await renderWithApp(EventsPage, { me: adminMe, route: '/events' })
    const rows = wrapper.findAll('[data-testid="events-table"] tbody tr')
    expect(rows).toHaveLength(2)
    expect(rows[0]?.text()).toContain('GET /p/e1')
    expect(rows[0]?.text()).toContain('942100')
    expect(rows[0]?.get('a').attributes('href')).toBe('/events/e1')
  })

  it('reads filters from the URL and sends them to the API', async () => {
    serve({ items: [] })
    const { wrapper } = await renderWithApp(EventsPage, {
      me: adminMe,
      route: '/events?site=shop&action=block&ip=203.0.113.7&country=DE&q=%2Fadmin&range=1h',
    })
    expect(eventCalls()[0]?.[1].params.query).toMatchObject({
      site: 'shop',
      action: 'block',
      ip: '203.0.113.7',
      country: 'DE',
      q: '/admin',
      limit: 50,
    })
    expect(wrapper.text()).toContain('No events match')
  })

  it('writes applied filters to the URL and reloads', async () => {
    serve({ items: [ev('e1')] })
    const { wrapper, router } = await renderWithApp(EventsPage, { me: adminMe, route: '/events' })
    const label = wrapper.findAll('label').find((l) => l.text().startsWith('Rule ID'))
    await wrapper.get(`[id="${label?.attributes('for')}"]`).setValue('942100')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(router.currentRoute.value.query).toEqual({ rule_id: '942100' })
    expect(eventCalls().at(-1)?.[1].params.query.rule_id).toBe('942100')
  })

  it('pages through older events with the cursor', async () => {
    serve((q) =>
      q.cursor === 'c2' ? { items: [ev('e3')] } : { items: [ev('e1')], next_cursor: 'c2' },
    )
    const { wrapper } = await renderWithApp(EventsPage, { me: adminMe, route: '/events' })
    const older = wrapper.findAll('button').find((b) => b.text().includes('Older events'))
    await older?.trigger('click')
    await flushPromises()
    expect(eventCalls().at(-1)?.[1].params.query.cursor).toBe('c2')
    expect(wrapper.text()).toContain('/p/e3')
    expect(wrapper.text()).toContain('Live updates run on the first page only')
    const newer = wrapper.findAll('button').find((b) => b.text().includes('Newer events'))
    await newer?.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('/p/e1')
  })

  it('polls on the first page and stops when paused', async () => {
    vi.useFakeTimers()
    serve({ items: [ev('e1')] })
    const { wrapper } = await renderWithApp(EventsPage, { me: adminMe, route: '/events' })
    expect(eventCalls()).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(5_000)
    expect(eventCalls()).toHaveLength(2)

    const pause = wrapper.findAll('button').find((b) => b.text().includes('Pause live updates'))
    await pause?.trigger('click')
    expect(pause?.attributes('aria-pressed')).toBe('true')
    await vi.advanceTimersByTimeAsync(20_000)
    expect(eventCalls()).toHaveLength(2)
    expect(wrapper.get('[data-testid="live-status"]').text()).toContain('paused')
  })

  it('keeps the table and warns when a live refresh fails', async () => {
    vi.useFakeTimers()
    serve({ items: [ev('e1')] })
    const { wrapper } = await renderWithApp(EventsPage, { me: adminMe, route: '/events' })
    api.GET.mockImplementation(async () => problem(500))
    await vi.advanceTimersByTimeAsync(5_000)
    expect(wrapper.text()).toContain('/p/e1')
    expect(wrapper.get('[role="alert"]').text()).toContain('live refresh failed')
  })

  it('shows an error state with retry when the first load fails', async () => {
    api.GET.mockImplementation(async () => problem(500))
    const { wrapper } = await renderWithApp(EventsPage, { me: adminMe, route: '/events' })
    expect(wrapper.get('[role="alert"]').text()).toContain('could not be loaded')
  })
})
