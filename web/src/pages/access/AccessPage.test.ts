import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { buttonNamed, control, dialogWithTitle, serve } from '@/pages/sites/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import AccessPage from './AccessPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

const config = () => ({
  schema_version: 1,
  global: {
    defaults: { acl: { deny_lists: ['known-bad'] } },
    ip_lists: [
      { name: 'office', cidrs: ['203.0.113.0/24'] },
      { name: 'known-bad', cidrs: ['198.51.100.7/32', '198.51.100.8/32'] },
      { name: 'unused', cidrs: [] },
    ],
    feeds: {
      geoip: { provider: 'dbip-lite', auto_update: true },
      reputation_lists: ['firehol_level1'],
      crowdsec: { enabled: false, lapi_url: '', allow_private: false, api_key_secret: 'kept' },
    },
  },
  sites: [
    {
      id: 'shop',
      hosts: ['shop.example.com'],
      upstreams: { targets: ['10.0.0.1:80'] },
      policy: { acl: { allow_lists: { add: ['office'] } } },
      endpoints: [
        { id: 'login', match: { path: '/login' }, policy: { acl: { deny_lists: ['known-bad'] } } },
      ],
    },
  ],
})

const feedItems = [
  { name: 'geoip', state: 'ok', last_success: '2026-10-29T01:00:00Z', entries: 250000 },
  { name: 'firehol_level1', state: 'never_loaded' },
  {
    name: 'spamhaus_drop',
    state: 'failed',
    last_success: '2026-10-28T01:00:00Z',
    last_error: 'download: 503 Service Unavailable',
    entries: 1400,
  },
  { name: 'crowdsec', state: 'disabled' },
]

async function mountAccess(me = adminMe, items: unknown[] = feedItems) {
  serve(api, {
    '/config': () => ok(config(), { etag: '"c1"' }),
    '/feeds/status': () => ok({ items }),
  })
  const view = await renderWithApp(AccessPage, { me, route: '/access' })
  const listsForm = view.wrapper.get('[data-testid="ip-lists-form"]')
  const feedsForm = view.wrapper.get('[data-testid="feeds-form"]')
  const submit = async (form: typeof listsForm) => {
    await form.trigger('submit')
    await flushPromises()
  }
  return { ...view, listsForm, feedsForm, submit }
}

interface PutBody {
  sites: unknown
  global: {
    defaults: unknown
    feeds: unknown
    ip_lists: { name: string; cidrs: string[] }[]
  }
}

const putCall = (n = 0) => api.PUT.mock.calls[n] as [string, { params: unknown; body: PutBody }]

beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

describe('AccessPage IP lists', () => {
  it('shows each list with its entry count and a locked name', async () => {
    const { wrapper } = await mountAccess()
    expect(wrapper.findAll('h1')).toHaveLength(1)
    const office = wrapper.get('[data-testid="ip-list-office"]')
    expect(office.text()).toContain('1 entry')
    expect(wrapper.get('[data-testid="ip-list-known-bad"]').text()).toContain('2 entries')
    expect((office.get('input').element as HTMLInputElement).disabled).toBe(true)
    expect((office.get('textarea').element as HTMLTextAreaElement).value).toBe('203.0.113.0/24')
  })

  it('creates a list and PUTs the whole document with If-Match', async () => {
    api.PUT.mockResolvedValue(ok({ id: 'v2' }, { etag: '"c2"' }))
    const { wrapper, listsForm, submit } = await mountAccess()
    await buttonNamed(wrapper, 'Add list').trigger('click')
    const fresh = wrapper.get('[data-testid="ip-list-new"]')
    await fresh.get('input').setValue('partners')
    await fresh.get('textarea').setValue('192.0.2.0/24\n\n2001:db8::/32\n')
    await submit(listsForm)
    const [path, init] = putCall()
    expect(path).toBe('/config')
    expect(init.params).toEqual({ header: { 'If-Match': '"c1"' } })
    expect(init.body.global.ip_lists).toEqual([
      ...config().global.ip_lists,
      { name: 'partners', cidrs: ['192.0.2.0/24', '2001:db8::/32'] },
    ])
    // Nothing else in the document is touched.
    expect(init.body.sites).toEqual(config().sites)
    expect(init.body.global.defaults).toEqual(config().global.defaults)
    expect(init.body.global.feeds).toEqual(config().global.feeds)

    // The next write uses the version returned by the first.
    await submit(listsForm)
    expect(putCall(1)[1].params).toEqual({ header: { 'If-Match': '"c2"' } })
  })

  it('puts server pointers on the name and on the offending entries', async () => {
    api.PUT.mockResolvedValue(
      problem(422, {
        errors: [
          { path: '/global/ip_lists/1/cidrs/1', code: 'invalid', message: 'not a valid CIDR' },
          { path: '/global/ip_lists/0/name', code: 'invalid', message: 'bad name' },
          { path: '/sites/0/policy/acl/allow_lists/0', code: 'not_found', message: 'no list' },
        ],
      }),
    )
    const { wrapper, listsForm, submit } = await mountAccess()
    await submit(listsForm)
    const bad = wrapper.get('[data-testid="ip-list-known-bad"]')
    expect(bad.text()).toContain('Entry 2 (198.51.100.8/32): not a valid CIDR')
    expect(wrapper.get('[data-testid="ip-list-office"]').text()).toContain('bad name')
    // A message about something this form does not render is still shown.
    expect(wrapper.text()).toContain('sites.0.policy.acl.allow_lists.0: no list')
  })

  it('offers a reload on 412', async () => {
    api.PUT.mockResolvedValue(problem(412))
    const { wrapper, listsForm, submit } = await mountAccess()
    await submit(listsForm)
    expect(wrapper.text()).toContain('changed by someone else')
    await buttonNamed(wrapper, 'Reload').trigger('click')
    await flushPromises()
    expect(api.GET.mock.calls.filter((c) => c[0] === '/config')).toHaveLength(2)
  })

  it('blocks deleting a list that policies reference and names the places', async () => {
    const { wrapper } = await mountAccess()
    await wrapper.get('button[aria-label="Delete list known-bad"]').trigger('click')
    const alert = wrapper.get('[data-testid="delete-blocked"]')
    expect(alert.text()).toContain('known-bad')
    expect(alert.text()).toContain('the global defaults')
    expect(alert.text()).toContain('endpoint login of site shop')
    expect(api.PUT).not.toHaveBeenCalled()

    await wrapper.get('button[aria-label="Delete list office"]').trigger('click')
    expect(wrapper.get('[data-testid="delete-blocked"]').text()).toContain('site shop')
    expect(api.PUT).not.toHaveBeenCalled()
  })

  it('deletes an unreferenced list after confirmation', async () => {
    api.PUT.mockResolvedValue(ok({}, { etag: '"c2"' }))
    const { wrapper } = await mountAccess()
    await wrapper.get('button[aria-label="Delete list unused"]').trigger('click')
    const dialog = dialogWithTitle(wrapper, 'Delete the list unused?')
    expect(dialog.element.open).toBe(true)
    expect(api.PUT).not.toHaveBeenCalled()
    await dialog.get('form').trigger('submit')
    await flushPromises()
    expect(putCall()[1].body.global.ip_lists.map((l: { name: string }) => l.name)).toEqual([
      'office',
      'known-bad',
    ])
  })

  it('is read-only for a viewer', async () => {
    const { wrapper } = await mountAccess(viewerMe)
    expect(wrapper.text()).toContain('read-only access')
    expect(wrapper.findAll('button').map((b) => b.text())).not.toContain('Add list')
    expect(wrapper.find('button[aria-label^="Delete list"]').exists()).toBe(false)
    expect(wrapper.find('button[type="submit"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="ip-list-office"]').attributes('disabled')).toBeDefined()
  })
})

describe('AccessPage feeds', () => {
  it('shows every state as text with a badge', async () => {
    const { wrapper } = await mountAccess()
    const table = wrapper.get('[data-testid="feeds-status"]')
    const rows = table.findAll('tbody tr').map((r) => r.text())
    expect(rows[0]).toContain('GeoIP database')
    expect(rows[0]).toContain('OK')
    expect(rows[1]).toContain('Never loaded')
    expect(rows[2]).toContain('Failed')
    expect(rows[2]).toContain('503 Service Unavailable')
    expect(rows[3]).toContain('Disabled')
    expect(table.findAll('tbody i.ti').length).toBeGreaterThan(0)
  })

  it('raises a prominent warning with the last error when a feed failed', async () => {
    const { wrapper } = await mountAccess()
    const banner = wrapper.get('[data-testid="feed-warning-spamhaus_drop"]')
    expect(banner.attributes('role')).toBe('alert')
    expect(banner.text()).toContain('Spamhaus DROP')
    expect(banner.text()).toContain('failed to update')
    expect(banner.text()).toContain('download: 503 Service Unavailable')
    expect(banner.text()).toContain('previous data stays in use')
  })

  it('warns about a stale feed and stays quiet when all is well', async () => {
    const stale = await mountAccess(adminMe, [
      { name: 'geoip', state: 'stale', last_success: '2026-10-01T00:00:00Z' },
    ])
    expect(stale.wrapper.get('[data-testid="feed-warning-geoip"]').text()).toContain('stale')
    stale.wrapper.unmount()

    const healthy = await mountAccess(adminMe, [{ name: 'geoip', state: 'ok', entries: 5 }])
    expect(healthy.wrapper.find('[data-testid^="feed-warning"]').exists()).toBe(false)
  })

  it('says how to load GeoIP by hand and where the secrets live', async () => {
    const { wrapper } = await mountAccess()
    expect(wrapper.text()).toContain('<data-dir>/geoip/dbip-country-lite.csv.gz')
    expect(wrapper.text()).toContain('no upload')
    expect(wrapper.text()).toContain('SHERLOCK_MAXMIND_LICENSE_KEY')
    expect(wrapper.text()).toContain('SHERLOCK_CROWDSEC_API_KEY')
  })

  it('saves feed settings into global.feeds, keeping unknown keys', async () => {
    api.PUT.mockResolvedValue(ok({}, { etag: '"c2"' }))
    const { wrapper, feedsForm, submit } = await mountAccess()
    await control(wrapper, 'Local API URL').setValue('https://crowdsec.example.com:8080')
    const spamhaus = wrapper
      .findAll('label')
      .find((l) => l.text() === 'Spamhaus DROP')
      ?.get('input')
    await spamhaus?.setValue(true)
    await submit(feedsForm)
    expect(putCall()[1].body.global.feeds).toEqual({
      geoip: { provider: 'dbip-lite', auto_update: true },
      reputation_lists: ['firehol_level1', 'spamhaus_drop'],
      crowdsec: {
        enabled: false,
        lapi_url: 'https://crowdsec.example.com:8080',
        allow_private: false,
        api_key_secret: 'kept',
      },
    })
    expect(putCall()[1].body.global.ip_lists).toEqual(config().global.ip_lists)
  })

  it('maps /global/feeds pointers onto the settings fields', async () => {
    api.PUT.mockResolvedValue(
      problem(422, {
        errors: [
          {
            path: '/global/feeds/crowdsec/lapi_url',
            code: 'forbidden',
            message: 'points at a metadata address',
          },
        ],
      }),
    )
    const { wrapper, feedsForm, submit } = await mountAccess()
    await control(wrapper, 'Local API URL').setValue('http://169.254.169.254/')
    await submit(feedsForm)
    expect(
      wrapper.get('#' + control(wrapper, 'Local API URL').attributes('id') + '-error').text(),
    ).toContain('metadata address')
  })
})
