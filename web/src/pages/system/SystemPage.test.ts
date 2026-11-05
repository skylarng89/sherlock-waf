import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'

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

const updater = { ...adminMe, permissions: [...adminMe.permissions, 'system:update'] }
const available = {
  current: '0.5.0',
  latest: '0.6.0',
  available: true,
  in_container: false,
}
const backupList = {
  items: [
    {
      name: 'sherlock-backup-2026.tar.gz',
      bytes: 2048,
      created_at: '2026-10-29T01:00:00Z',
      encrypted: false,
    },
  ],
}

async function check(wrapper: { get(s: string): { trigger(e: string): Promise<void> } }) {
  await wrapper.get('[data-testid="update-check"]').trigger('click')
  await vi.waitFor(() => expect(api.GET).toHaveBeenCalledWith('/system/update'))
  await new Promise((r) => setTimeout(r, 0))
}

function serve(overrides: Record<string, unknown> = {}) {
  api.GET.mockImplementation(async (path: string) => {
    const map: Record<string, unknown> = {
      '/system/info': ok(info),
      '/system/status': ok(status),
      '/feeds/status': ok(feeds),
      '/system/update': ok({ ...available, available: false, latest: '0.5.0' }),
      '/system/backups': ok({ items: [] }),
      ...overrides,
    }
    return (map[path] as ReturnType<typeof ok>) ?? problem(404)
  })
}

describe('system page', () => {
  it('shows version, storage and feed health', async () => {
    serve()
    const { wrapper } = await renderWithApp(SystemPage, { me: adminMe, route: '/system' })
    expect(api.GET).not.toHaveBeenCalledWith('/system/update')
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

  it('lists backups', async () => {
    serve({ '/system/backups': ok(backupList) })
    const { wrapper } = await renderWithApp(SystemPage, { me: adminMe, route: '/system' })
    const rows = wrapper.findAll('[data-testid="backups-table"] tbody tr')
    expect(rows).toHaveLength(1)
    expect(rows[0]?.text()).toContain('sherlock-backup-2026.tar.gz')
    expect(rows[0]?.text()).toContain('2 KiB')
  })

  it('shows update status to a viewer without the apply button', async () => {
    serve({ '/system/update': ok(available) })
    const { wrapper } = await renderWithApp(SystemPage, { me: viewerMe, route: '/system' })
    await check(wrapper)
    expect(wrapper.get('[data-testid="update-section"]').text()).toContain('Update available')
    expect(wrapper.find('[data-testid="update-apply"]').exists()).toBe(false)
  })

  it('stages an update after confirmation and says a restart is needed', async () => {
    serve({ '/system/update': ok(available) })
    api.POST.mockResolvedValue(
      ok({ from: '0.5.0', to: '0.6.0', state: 'staged', restart: 'Restart the service.' }),
    )
    const { wrapper } = await renderWithApp(SystemPage, { me: updater, route: '/system' })
    await check(wrapper)
    expect(wrapper.text()).toContain('does not restart Sherlock')
    await wrapper.get('[data-testid="update-apply"]').trigger('click')
    expect(api.POST).not.toHaveBeenCalled()
    await wrapper.get('dialog form').trigger('submit')
    await vi.waitFor(() => expect(api.POST).toHaveBeenCalledWith('/system/update/apply'))
    await vi.waitFor(() =>
      expect(wrapper.get('[data-testid="update-result"]').text()).toContain('is staged'),
    )
    expect(wrapper.get('[data-testid="update-result"]').text()).toContain('Restart the service.')
  })

  it('hides the button in containers and when a release needs a manual step', async () => {
    serve({ '/system/update': ok({ ...available, in_container: true }) })
    const a = await renderWithApp(SystemPage, { me: updater, route: '/system' })
    await check(a.wrapper)
    expect(a.wrapper.find('[data-testid="update-apply"]').exists()).toBe(false)
    expect(a.wrapper.find('[data-testid="update-container"]').exists()).toBe(true)
    serve({ '/system/update': ok({ ...available, reason: 'min_upgrade_from 0.5.5' }) })
    const b = await renderWithApp(SystemPage, { me: updater, route: '/system' })
    await check(b.wrapper)
    expect(b.wrapper.find('[data-testid="update-apply"]').exists()).toBe(false)
    expect(b.wrapper.text()).toContain('min_upgrade_from 0.5.5')
  })

  it.each([
    [501, 'not supported'],
    [502, 'could not be reached'],
  ])('handles a %i from the update check gracefully', async (status, text) => {
    serve({ '/system/update': problem(status) })
    const { wrapper } = await renderWithApp(SystemPage, { me: updater, route: '/system' })
    await check(wrapper)
    expect(wrapper.get('[data-testid="update-problem"]').text()).toContain(text)
    expect(wrapper.find('[data-testid="sys-version"]').exists()).toBe(true)
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
  })

  it('shows the reason when applying fails', async () => {
    serve({ '/system/update': ok(available) })
    api.POST.mockResolvedValue(problem(502, { detail: 'checksum mismatch' }))
    const { wrapper } = await renderWithApp(SystemPage, { me: updater, route: '/system' })
    await check(wrapper)
    await wrapper.get('[data-testid="update-apply"]').trigger('click')
    await wrapper.get('dialog form').trigger('submit')
    await vi.waitFor(() =>
      expect(wrapper.get('[data-testid="update-error"]').text()).toContain('checksum mismatch'),
    )
  })
})
