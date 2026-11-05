import { flushPromises } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { buttonNamed, control, dialogWithTitle, serve } from '@/pages/sites/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import AlertsPage from './AlertsPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

const stamp = { created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z' }
const drops = {
  id: 'drops',
  name: 'Events dropped',
  kind: 'events_dropped',
  enabled: true,
  severity: 'critical',
  cooldown_seconds: 3600,
  channel_ids: ['ops'],
  params: {},
  ...stamp,
}
const blocks = {
  id: 'blocks',
  name: 'Shop blocks',
  kind: 'blocks_threshold',
  enabled: true,
  severity: 'warning',
  cooldown_seconds: 900,
  channel_ids: [],
  params: { site_id: 'shop', threshold: 50, window_seconds: 300 },
  ...stamp,
}
const channel = {
  id: 'ops',
  name: 'Ops Slack',
  type: 'slack',
  enabled: true,
  settings: {},
  ...stamp,
}

let channels: unknown[] = [channel]

async function mountPage(me = adminMe) {
  serve(api, {
    '/alert-rules': () => ok({ items: [drops, blocks] }),
    '/alerts/status': () =>
      ok({
        items: [
          {
            rule_id: 'drops',
            firing: true,
            suppressed: 4,
            last_evaluated: '2026-10-29T11:59:30Z',
            last_fired: '2026-10-29T11:00:00Z',
            last_error: '',
          },
          { rule_id: 'blocks', firing: false, suppressed: 0 },
        ],
      }),
    '/notification-channels': () => ok({ items: channels }),
    '/sites': () => ok({ items: [{ id: 'shop', hosts: ['s'], upstreams: { targets: ['t'] } }] }),
  })
  return renderWithApp(AlertsPage, { me, route: '/integrations/alerts' })
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] })
  vi.setSystemTime(new Date('2026-10-29T12:00:00Z'))
  channels = [channel]
  Object.values(api).forEach((fn) => fn.mockReset())
  api.PUT.mockResolvedValue(ok({}))
})
afterEach(() => vi.useRealTimers())

describe('AlertsPage', () => {
  it('lists rules with live state, channel names and cool-downs', async () => {
    const { wrapper } = await mountPage()
    const row = wrapper.get('[data-testid="alert-drops"]')
    expect(row.get('[data-testid="firing"]').text()).toContain('Firing')
    expect(row.text()).toContain('Critical')
    expect(row.text()).toContain('1 h')
    expect(row.text()).toContain('Ops Slack')
    expect(row.text()).toContain('30 seconds ago')
    expect(row.text()).toContain('Held back')
    const other = wrapper.get('[data-testid="alert-blocks"]')
    expect(other.find('[data-testid="firing"]').exists()).toBe(false)
    expect(other.text()).toContain('OK')
    expect(other.text()).toContain('15 min')
  })

  it('is read-only for viewers', async () => {
    const { wrapper } = await mountPage(viewerMe)
    expect(wrapper.find('[data-testid="alert-add"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="alert-drops"] button').exists()).toBe(false)
  })

  it('creates a blocks_threshold rule with params, channels and the default cool-down', async () => {
    const { wrapper } = await mountPage()
    await buttonNamed(wrapper, 'Add alert rule').trigger('click')
    await control(wrapper, 'Name').setValue('Login blocks')
    await control(wrapper, 'Site').setValue('shop')
    await control(wrapper, 'Blocks threshold').setValue('20')
    await wrapper.get('fieldset input[type="checkbox"]').setValue(true)
    await dialogWithTitle(wrapper, 'Add alert rule').get('form').trigger('submit')
    await flushPromises()
    expect(api.PUT).toHaveBeenCalledWith('/alert-rules/{id}', {
      params: { path: { id: 'login-blocks' } },
      body: {
        name: 'Login blocks',
        kind: 'blocks_threshold',
        enabled: true,
        severity: 'warning',
        cooldown_seconds: 900,
        channel_ids: ['ops'],
        params: { site_id: 'shop', threshold: 20, window_seconds: 300 },
      },
    })
  })

  it('switches params with the kind', async () => {
    const { wrapper } = await mountPage()
    await buttonNamed(wrapper, 'Add alert rule').trigger('click')
    await control(wrapper, 'Name').setValue('Certs')
    await control(wrapper, 'Condition').setValue('cert_expiring')
    await dialogWithTitle(wrapper, 'Add alert rule').get('form').trigger('submit')
    await flushPromises()
    expect(api.PUT.mock.calls[0]?.[1].body).toMatchObject({
      kind: 'cert_expiring',
      params: { days: 14 },
    })
  })

  it('rejects a cool-down outside 60 to 604800 seconds', async () => {
    const { wrapper } = await mountPage()
    await buttonNamed(wrapper, 'Add alert rule').trigger('click')
    await control(wrapper, 'Name').setValue('Fast')
    await control(wrapper, 'Cool-down').setValue('10')
    await dialogWithTitle(wrapper, 'Add alert rule').get('form').trigger('submit')
    await flushPromises()
    expect(api.PUT).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('between 60 and 604800 seconds')
  })

  it('points to the channels page when none exist', async () => {
    channels = []
    const { wrapper } = await mountPage()
    await buttonNamed(wrapper, 'Add alert rule').trigger('click')
    const hint = wrapper.get('[data-testid="no-channels"]')
    expect(hint.get('a').attributes('href')).toBe('/integrations/channels')
  })

  it('shows the server validation message inline', async () => {
    api.PUT.mockResolvedValue(problem(422, { detail: 'threshold must be at least 1' }))
    const { wrapper } = await mountPage()
    await wrapper.get('button[aria-label="Edit Shop blocks"]').trigger('click')
    await dialogWithTitle(wrapper, 'Edit alert rule').get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.get('[data-testid="form-error"]').text()).toContain(
      'threshold must be at least 1',
    )
    expect(api.PUT.mock.calls[0]?.[1].body.params).toEqual({
      site_id: 'shop',
      threshold: 50,
      window_seconds: 300,
    })
  })

  it('polls status every 15 seconds and stops when the page goes away', async () => {
    const { wrapper } = await mountPage()
    const calls = () => api.GET.mock.calls.filter((c) => c[0] === '/alerts/status').length
    expect(calls()).toBe(1)
    await vi.advanceTimersByTimeAsync(15_000)
    expect(calls()).toBe(2)
    wrapper.unmount()
    await vi.advanceTimersByTimeAsync(60_000)
    expect(calls()).toBe(2)
  })
})
