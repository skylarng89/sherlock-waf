import { flushPromises } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { buttonNamed, control, dialogWithTitle, serve } from '@/pages/sites/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import BansPage from './BansPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

const NOW = new Date('2026-10-29T12:00:00Z')
const bans = [
  {
    id: 'b1',
    ip: '203.0.113.9',
    source: 'manual',
    reason: 'scanner',
    created_by: 'ada',
    created_at: '2026-10-29T11:00:00Z',
    until: '2026-10-29T14:00:00Z',
  },
  {
    id: 'b2',
    ip: '198.51.100.4',
    site_id: 'shop',
    source: 'auto',
    reason: '20 blocks in 5m',
    created_by: 'system',
    created_at: '2026-10-29T11:50:00Z',
    until: '2026-10-29T12:20:00Z',
  },
  {
    id: 'b3',
    ip: '192.0.2.77',
    source: 'crowdsec',
    reason: 'crowdsecurity/http-probing',
    created_by: 'crowdsec',
    created_at: '2026-10-29T10:00:00Z',
    until: '2026-10-30T12:00:00Z',
  },
]

let list = bans
async function mountBans(me = adminMe) {
  serve(api, {
    '/bans': () => ok({ items: list }),
    '/sites': () => ok({ items: [{ id: 'shop', hosts: ['s'], upstreams: { targets: ['t'] } }] }),
  })
  return renderWithApp(BansPage, { me, route: '/bans' })
}

const submitCreate = async (wrapper: Awaited<ReturnType<typeof mountBans>>['wrapper']) => {
  const form = wrapper.get('section[aria-labelledby="create-ban-title"] form')
  await form.trigger('submit')
  await flushPromises()
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] })
  vi.setSystemTime(NOW)
  list = bans
  Object.values(api).forEach((fn) => fn.mockReset())
})
afterEach(() => vi.useRealTimers())

describe('BansPage', () => {
  it('lists bans with scope, source badge, relative and absolute expiry', async () => {
    const { wrapper } = await mountBans()
    expect(wrapper.findAll('h1')).toHaveLength(1)
    const rows = wrapper.get('[data-testid="bans-table"]').findAll('tbody tr')
    expect(rows).toHaveLength(3)
    const first = wrapper.get('[data-testid="ban-b1"]')
    expect(first.text()).toContain('203.0.113.9')
    expect(first.text()).toContain('All sites')
    expect(first.text()).toContain('Manual')
    expect(first.text()).toContain('ada')
    expect(first.text()).toContain('in 2 hours')
    expect(first.get('time').attributes('datetime')).toBe('2026-10-29T14:00:00Z')
    const auto = wrapper.get('[data-testid="ban-b2"]')
    expect(auto.text()).toContain('Site shop')
    expect(auto.text()).toContain('Automatic')
    expect(auto.text()).toContain('in 20 minutes')
    expect(wrapper.get('[data-testid="ban-b3"]').text()).toContain('CrowdSec')
  })

  it('shows an empty state', async () => {
    list = []
    const { wrapper } = await mountBans()
    expect(wrapper.text()).toContain('No active bans')
    expect(wrapper.find('table').exists()).toBe(false)
  })

  it('shows a retryable error when the list cannot load', async () => {
    serve(api, { '/bans': () => problem(500), '/sites': () => ok({ items: [] }) })
    const { wrapper } = await renderWithApp(BansPage, { me: adminMe, route: '/bans' })
    expect(wrapper.get('[role="alert"]').text()).toContain('could not be loaded')
  })

  it('refreshes every 30 seconds and can be paused and resumed', async () => {
    const { wrapper } = await mountBans()
    const calls = () => api.GET.mock.calls.filter((c) => c[0] === '/bans').length
    expect(calls()).toBe(1)
    await vi.advanceTimersByTimeAsync(30_000)
    expect(calls()).toBe(2)
    await buttonNamed(wrapper, 'Pause refresh').trigger('click')
    expect(wrapper.text()).toContain('Automatic refresh is paused')
    await vi.advanceTimersByTimeAsync(90_000)
    expect(calls()).toBe(2)
    await buttonNamed(wrapper, 'Resume refresh').trigger('click')
    await flushPromises()
    expect(calls()).toBe(3)
    await vi.advanceTimersByTimeAsync(30_000)
    expect(calls()).toBe(4)
  })

  it('keeps the table when a background refresh fails', async () => {
    const { wrapper } = await mountBans()
    api.GET.mockImplementation((path: string) =>
      Promise.resolve(path === '/bans' ? problem(500) : ok({ items: [] })),
    )
    await vi.advanceTimersByTimeAsync(30_000)
    expect(wrapper.find('[data-testid="ban-b1"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('could not be refreshed')
  })

  describe('creating a ban', () => {
    it('POSTs the address, duration preset, site and reason', async () => {
      api.POST.mockResolvedValue(ok({ id: 'b9' }, { status: 201 }))
      const { wrapper } = await mountBans()
      await control(wrapper, 'IP address').setValue(' 203.0.113.50 ')
      await control(wrapper, 'Site').setValue('shop')
      await wrapper.get('input[type="radio"][value="24h"]').setValue(true)
      await control(wrapper, 'Reason').setValue('credential stuffing')
      await submitCreate(wrapper)
      expect(api.POST).toHaveBeenCalledWith('/bans', {
        body: {
          ip: '203.0.113.50',
          site_id: 'shop',
          duration_seconds: 86_400,
          reason: 'credential stuffing',
        },
      })
      expect((control(wrapper, 'IP address').element as HTMLInputElement).value).toBe('')
      // The list is reloaded.
      expect(api.GET.mock.calls.filter((c) => c[0] === '/bans')).toHaveLength(2)
    })

    it('defaults to every site, one hour, and omits an empty reason', async () => {
      api.POST.mockResolvedValue(ok({ id: 'b9' }, { status: 201 }))
      const { wrapper } = await mountBans()
      await control(wrapper, 'IP address').setValue('2001:db8::1')
      await submitCreate(wrapper)
      expect(api.POST).toHaveBeenCalledWith('/bans', {
        body: { ip: '2001:db8::1', duration_seconds: 3_600 },
      })
    })

    it('converts a custom number of hours to seconds', async () => {
      api.POST.mockResolvedValue(ok({ id: 'b9' }, { status: 201 }))
      const { wrapper } = await mountBans()
      await control(wrapper, 'IP address').setValue('192.0.2.1')
      await wrapper.get('input[type="radio"][value="custom"]').setValue(true)
      await control(wrapper, 'Hours').setValue('1.5')
      await submitCreate(wrapper)
      expect(api.POST.mock.calls[0]?.[1]).toMatchObject({ body: { duration_seconds: 5_400 } })
    })

    it('validates the address and the custom duration before sending', async () => {
      const { wrapper } = await mountBans()
      await wrapper.get('input[type="radio"][value="custom"]').setValue(true)
      await control(wrapper, 'Hours').setValue('2000')
      await submitCreate(wrapper)
      expect(api.POST).not.toHaveBeenCalled()
      expect(wrapper.text()).toContain('Enter an IP address')
      expect(wrapper.text()).toContain('between 1 minute and 30 days')
    })

    it('shows a clear alert when the server refuses to ban your own address (409)', async () => {
      api.POST.mockResolvedValue(
        problem(409, { detail: 'you would ban the address you are using right now' }),
      )
      const { wrapper } = await mountBans()
      await control(wrapper, 'IP address').setValue('198.18.0.1')
      await submitCreate(wrapper)
      const alert = wrapper.get('section[aria-labelledby="create-ban-title"] [role="alert"]')
      expect(alert.text()).toContain('cannot ban the address you are connecting from')
      // Editing the address clears the message.
      await control(wrapper, 'IP address').setValue('198.18.0.2')
      expect(
        wrapper.find('section[aria-labelledby="create-ban-title"] p[role="alert"]').exists(),
      ).toBe(false)
    })

    it('puts a 400 about the address on the address field', async () => {
      api.POST.mockResolvedValue(
        problem(400, { detail: 'ip must be a single IPv4 or IPv6 address.' }),
      )
      const { wrapper } = await mountBans()
      await control(wrapper, 'IP address').setValue('10.0.0.0/8')
      await submitCreate(wrapper)
      const id = control(wrapper, 'IP address').attributes('id')
      expect(wrapper.get(`[id="${id}-error"]`).text()).toContain('single IPv4 or IPv6')
    })
  })

  describe('lifting a ban', () => {
    it('asks for confirmation, then DELETEs and refreshes', async () => {
      api.DELETE.mockResolvedValue(ok(undefined, { status: 204 }))
      const { wrapper } = await mountBans()
      await wrapper.get('button[aria-label="Lift the ban on 203.0.113.9"]').trigger('click')
      const dialog = dialogWithTitle(wrapper, 'Lift the ban on 203.0.113.9?')
      expect(dialog.element.open).toBe(true)
      expect(api.DELETE).not.toHaveBeenCalled()
      await dialog.get('form').trigger('submit')
      await flushPromises()
      expect(api.DELETE).toHaveBeenCalledWith('/bans/{id}', { params: { path: { id: 'b1' } } })
      expect(api.GET.mock.calls.filter((c) => c[0] === '/bans')).toHaveLength(2)
    })

    it('does nothing when the confirmation is cancelled', async () => {
      const { wrapper } = await mountBans()
      await wrapper.get('button[aria-label="Lift the ban on 203.0.113.9"]').trigger('click')
      const dialog = dialogWithTitle(wrapper, 'Lift the ban on 203.0.113.9?')
      await buttonNamed(dialog, 'Cancel').trigger('click')
      await flushPromises()
      expect(api.DELETE).not.toHaveBeenCalled()
    })
  })

  it('is read-only for a viewer', async () => {
    const { wrapper } = await mountBans(viewerMe)
    expect(wrapper.text()).toContain('read-only access')
    expect(wrapper.find('section[aria-labelledby="create-ban-title"]').exists()).toBe(false)
    expect(wrapper.find('button[aria-label^="Lift"]').exists()).toBe(false)
    expect(wrapper.findAll('[data-testid^="ban-"]')).toHaveLength(3)
  })
})
