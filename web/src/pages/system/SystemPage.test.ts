import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp } from '@/test-utils'

import SystemPage from './SystemPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>
beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

const info = {
  version: '0.5.0',
  commit: 'abc1234',
  crs_version: '4.8.0',
  database: 'sqlite',
  features: ['bot', 'ratelimit'],
  ready: true,
  config_version: 'V12',
  audit_head: { seq: 42, hash: 'deadbeef' },
}
const status = {
  events_stored: 1234567,
  events_published: 1234600,
  events_dropped: 0,
  data_dir_bytes: 5 * 1024 * 1024,
  retention_days: 30,
}
const feeds = {
  items: [
    { name: 'geoip', state: 'ok', last_success: '2026-10-29T01:00:00Z', entries: 250000 },
    { name: 'spamhaus_drop', state: 'failed', last_error: 'timeout' },
    { name: 'firehol_level1', state: 'never_loaded' },
  ],
}

function serve(overrides: Record<string, unknown> = {}) {
  api.GET.mockImplementation(async (path: string) => {
    const map: Record<string, unknown> = {
      '/system/info': ok(info),
      '/system/status': ok(status),
      '/feeds/status': ok(feeds),
      ...overrides,
    }
    return (map[path] as ReturnType<typeof ok>) ?? problem(404)
  })
}

describe('system page', () => {
  it('shows version, storage and feed health', async () => {
    serve()
    const { wrapper } = await renderWithApp(SystemPage, { me: adminMe, route: '/system' })
    expect(wrapper.get('[data-testid="sys-version"]').text()).toBe('0.5.0')
    expect(wrapper.get('[data-testid="sys-crs"]').text()).toBe('4.8.0')
    expect(wrapper.get('[data-testid="sys-stored"]').text()).toBe('1,234,567')
    expect(wrapper.get('[data-testid="sys-disk"]').text()).toBe('5 MiB')
    expect(wrapper.get('[data-testid="sys-dropped"]').text()).toBe('0')
    const rows = wrapper.findAll('[data-testid="feeds-table"] tbody tr')
    expect(rows).toHaveLength(3)
    expect(rows[1]?.text()).toContain('Failed')
    expect(rows[1]?.text()).toContain('timeout')
    expect(rows[2]?.text()).toContain('Never')
  })

  it('warns when events were dropped', async () => {
    serve({ '/system/status': ok({ ...status, events_dropped: 17, data_dir_truncated: true }) })
    const { wrapper } = await renderWithApp(SystemPage, { me: adminMe, route: '/system' })
    expect(wrapper.get('[data-testid="sys-dropped"]').text()).toBe('17')
    expect(wrapper.text()).toContain('pipeline was overloaded')
    expect(wrapper.get('[data-testid="sys-disk"]').text()).toContain('≥')
  })

  it('keeps the sections that loaded when one request fails', async () => {
    serve({ '/feeds/status': problem(500) })
    const { wrapper } = await renderWithApp(SystemPage, { me: adminMe, route: '/system' })
    expect(wrapper.get('[role="alert"]').text()).toContain('could not be loaded')
    expect(wrapper.find('[data-testid="sys-version"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="feeds-table"]').exists()).toBe(false)
  })
})
