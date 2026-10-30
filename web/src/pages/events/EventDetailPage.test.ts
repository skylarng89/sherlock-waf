import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp } from '@/test-utils'

import EventDetailPage from './EventDetailPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>
beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

const PAYLOAD = '<img src=x onerror="window.__xss=1"><script>window.__xss=2</script>'

const hostile = {
  id: 'e9',
  ts: '2026-10-29T11:00:00Z',
  site_id: 'shop',
  mode: 'detect',
  action: 'log',
  request: {
    method: 'GET',
    host: PAYLOAD,
    path: `/${PAYLOAD}`,
    query: PAYLOAD,
    headers: { 'User-Agent': PAYLOAD, [`X-${PAYLOAD}`]: 'v' },
    body_excerpt: PAYLOAD,
  },
  client: { ip: '203.0.113.7', country: 'DE', asn: 64500, reputation: 3 },
  anomaly_score: { inbound: 10, outbound: 0 },
  findings: [
    {
      rule_id: '942100',
      module: 'waf',
      severity: 'critical',
      score: 5,
      message: PAYLOAD,
      matched: PAYLOAD,
      target: 'ARGS:q',
      tags: [PAYLOAD],
    },
  ],
}

describe('event detail', () => {
  it('renders every field of a hostile event as text', async () => {
    api.GET.mockImplementation(async (path: string) =>
      path === '/events/{id}' ? ok(hostile) : ok({ items: [] }),
    )
    const { wrapper } = await renderWithApp(EventDetailPage, {
      me: adminMe,
      route: '/events/e9',
    })
    const detail = wrapper.get('[data-testid="event-detail"]')
    expect(detail.find('img').exists()).toBe(false)
    expect(detail.find('script').exists()).toBe(false)
    expect(detail.text()).toContain(PAYLOAD)
    expect(wrapper.get('[data-testid="request-body"]').text()).toBe(PAYLOAD)
    expect((window as unknown as { __xss?: number }).__xss).toBeUndefined()
  })

  it('shows findings, scores and the similar-events count', async () => {
    api.GET.mockImplementation(async (path: string) =>
      path === '/events/{id}'
        ? ok({
            ...hostile,
            request: { method: 'GET', path: '/x' },
            findings: [hostile.findings[0]],
          })
        : ok({ items: [{ id: 'e9' }, { id: 'a' }, { id: 'b' }] }),
    )
    const { wrapper } = await renderWithApp(EventDetailPage, { me: adminMe, route: '/events/e9' })
    expect(wrapper.get('[data-testid="findings-table"]').text()).toContain('942100')
    expect(wrapper.text()).toContain('Inbound')
    expect(wrapper.get('[data-testid="similar-count"]').text()).toContain('2 other events')
  })

  it('says so when the event no longer exists', async () => {
    api.GET.mockImplementation(async () => problem(404))
    const { wrapper } = await renderWithApp(EventDetailPage, { me: adminMe, route: '/events/zz' })
    expect(wrapper.get('[role="alert"]').text()).toContain('does not exist')
  })
})
