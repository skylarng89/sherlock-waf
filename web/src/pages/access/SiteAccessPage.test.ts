import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import type { Policy } from '@/pages/sites/lib/layers'
import {
  blog,
  buttonNamed,
  control,
  errorOf,
  overrideToggle,
  serve,
  shop,
  type Site,
} from '@/pages/sites/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import SiteAccessPage from './SiteAccessPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

const globalLimit = {
  name: 'global-per-ip',
  match: { paths: ['/*'] },
  key: 'ip',
  limit: 600,
  window: '1m',
  action: 'block' as const,
}
const defaults: Policy = {
  acl: { allow_lists: ['office', 'vpn'], deny_lists: ['known-bad'] },
  rate_limits: [globalLimit, { name: 'login', limit: 10, window: '1m', action: 'challenge' }],
}

async function mount(
  section: 'acl' | 'rate-limits',
  options: { me?: typeof adminMe; policy?: Policy } = {},
) {
  const site: Site = { ...shop, policy: options.policy ?? shop.policy }
  serve(api, {
    '/sites': () => ok({ items: [blog, site] }, { etag: '"v7"' }),
    '/defaults': () => ok(defaults),
    '/config': () =>
      ok({
        schema_version: 1,
        global: {
          ip_lists: [
            { name: 'office', cidrs: [] },
            { name: 'partners', cidrs: [] },
          ],
        },
        sites: [],
      }),
    '/sites/{site}/effective-policy': () =>
      ok({
        site: 'shop',
        matched_endpoint: 'login',
        policy: {
          acl: {
            allow_lists: ['office'],
            country_mode: 'deny',
            countries: ['KP'],
            allow_bypass_waf: false,
          },
          rate_limits: [globalLimit],
          auto_ban: {
            enabled: true,
            blocks_threshold: 20,
            window: 300_000_000_000,
            ban_duration: 1_800_000_000_000,
          },
        },
        sources: {
          'acl.allow_lists': 'site',
          'acl.countries.mode': 'global',
          'acl.countries.list': 'global',
          'rate_limits.global-per-ip': 'global',
          auto_ban: 'site',
        },
      }),
  })
  const view = await renderWithApp(SiteAccessPage, {
    me: options.me ?? adminMe,
    route: `/sites/shop/${section}`,
    props: { section },
  })
  const submit = async () => {
    await view.wrapper.get('form').trigger('submit')
    await flushPromises()
  }
  return { ...view, submit }
}

const patch = (n = 0) =>
  api.PATCH.mock.calls[n] as [string, { params: unknown; headers: unknown; body: unknown }]

const press = async (
  input: { setValue(v: string): Promise<void>; trigger(e: string): Promise<void> },
  value: string,
) => {
  await input.setValue(value)
  await input.trigger('keydown.enter')
}

beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

describe('site ACL tab', () => {
  it('shows the inherited lists with their source', async () => {
    const { wrapper } = await mount('acl')
    expect(wrapper.get('h1').text()).toBe('Shop')
    const inherited = wrapper.findAll('[data-testid="inherited-value"]').map((o) => o.text())
    expect(inherited).toContain('office, vpn')
    expect(inherited).toContain('known-bad')
    expect(wrapper.text()).toContain('Inherited from global defaults')
    expect(wrapper.text()).toContain('still inspected by the WAF')
  })

  it('replace mode sends an array that replaces the inherited list', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
    const { wrapper, submit } = await mount('acl')
    await overrideToggle(wrapper, 'Allow lists').setValue(true)
    // Starts from the inherited names; the radio says it replaces them.
    expect(wrapper.text()).toContain('Only the names below apply')
    await press(control(wrapper, 'Allow lists'), 'partners')
    await wrapper.get('button[aria-label="Remove vpn"]').trigger('click')
    await submit()
    const [path, init] = patch()
    expect(path).toBe('/sites/{site}')
    expect(init.params).toEqual({ path: { site: 'shop' }, header: { 'If-Match': '"v7"' } })
    expect(init.headers).toEqual({ 'Content-Type': 'application/merge-patch+json' })
    expect(init.body).toEqual({ policy: { acl: { allow_lists: ['office', 'partners'] } } })
  })

  it('keeps an explicitly empty replacement list', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
    const { wrapper, submit } = await mount('acl')
    await overrideToggle(wrapper, 'Allow lists').setValue(true)
    await wrapper.get('button[aria-label="Remove office"]').trigger('click')
    await wrapper.get('button[aria-label="Remove vpn"]').trigger('click')
    await submit()
    expect(patch()[1].body).toEqual({ policy: { acl: { allow_lists: [] } } })
  })

  it('edit mode sends {add, remove} that edits the inherited list', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
    const { wrapper, submit } = await mount('acl')
    await overrideToggle(wrapper, 'Allow lists').setValue(true)
    await wrapper.get('input[type="radio"][value="edit"]').setValue(true)
    expect(wrapper.text()).toContain('Starts from the inherited list')
    await press(control(wrapper, 'Allow lists'), 'partners')
    await press(wrapper.get('input[aria-label="Name to remove from Allow lists"]'), 'vpn')
    await submit()
    expect(patch()[1].body).toEqual({
      policy: { acl: { allow_lists: { add: ['partners'], remove: ['vpn'] } } },
    })
  })

  it('edit mode with only additions omits remove', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
    const { wrapper, submit } = await mount('acl')
    await overrideToggle(wrapper, 'Deny lists').setValue(true)
    await wrapper.get('input[type="radio"][value="edit"]').setValue(true)
    await press(control(wrapper, 'Deny lists'), 'partners')
    await submit()
    expect(patch()[1].body).toEqual({ policy: { acl: { deny_lists: { add: ['partners'] } } } })
  })

  it('serialises switching an existing edit back to a replacement list', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
    const { wrapper, submit } = await mount('acl', {
      policy: { mode: 'detect', acl: { allow_lists: { add: ['partners'] } } },
    })
    await wrapper.get('input[type="radio"][value="replace"]').setValue(true)
    await submit()
    // Applying the edit to the inherited [office, vpn] gives the equivalent replacement.
    expect(patch()[1].body).toEqual({
      policy: { acl: { allow_lists: ['office', 'vpn', 'partners'] } },
    })
  })

  it('sends countries, reputation and the bypass flag, and warns about the bypass', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
    const { wrapper, submit } = await mount('acl')
    await overrideToggle(wrapper, 'Country rule').setValue(true)
    await control(wrapper, 'Country rule').setValue('allow')
    await press(wrapper.get('input[aria-label="Country code to add"]'), 'de')
    await overrideToggle(wrapper, 'Skip WAF inspection').setValue(true)
    expect(wrapper.text()).toContain('still inspected by the WAF')
    await control(wrapper, 'Skip WAF inspection').setValue(true)
    expect(wrapper.text()).toContain('will not be inspected by the WAF at all')
    await submit()
    expect(patch()[1].body).toEqual({
      policy: { acl: { countries: { mode: 'allow', list: ['DE'] }, allow_bypass_waf: true } },
    })
  })

  it('refuses a malformed country code inline', async () => {
    const { wrapper } = await mount('acl')
    await overrideToggle(wrapper, 'Country rule').setValue(true)
    await press(wrapper.get('input[aria-label="Country code to add"]'), 'germany')
    expect(wrapper.text()).toContain('GERMANY is not a two-letter country code')
  })

  it('takes the password hash as given and explains the missing CLI', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
    const { wrapper, submit } = await mount('acl')
    await overrideToggle(wrapper, 'Password gate').setValue(true)
    const hash = control(wrapper, 'Password hash')
    expect(hash.attributes('type')).toBe('password')
    await control(wrapper, 'Username').setValue('admin')
    await hash.setValue('$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA')
    expect(wrapper.text()).toContain('sherlock hash-password')
    expect(wrapper.text()).not.toContain('coming soon')
    await submit()
    expect(patch()[1].body).toEqual({
      policy: {
        acl: {
          password_gate: {
            enabled: true,
            username: 'admin',
            password_hash: '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA',
          },
        },
      },
    })
  })

  it('does not call the server when nothing changed', async () => {
    const { submit } = await mount('acl')
    await submit()
    expect(api.PATCH).not.toHaveBeenCalled()
  })

  it('maps /sites/<n>/policy/acl pointers onto the fields', async () => {
    api.PATCH.mockResolvedValue(
      problem(422, {
        errors: [
          { path: '/sites/1/policy/acl/allow_lists/1', code: 'not_found', message: 'no such list' },
          { path: '/sites/1/policy/bot/enabled', code: 'x', message: 'unrelated' },
        ],
      }),
    )
    const { wrapper, submit } = await mount('acl')
    await overrideToggle(wrapper, 'Allow lists').setValue(true)
    await press(control(wrapper, 'Allow lists'), 'nope')
    await submit()
    expect(errorOf(wrapper, 'Allow lists')).toBe('Line 2: no such list')
    expect(wrapper.text()).toContain('bot.enabled: unrelated')
  })

  it('offers a reload on 412', async () => {
    api.PATCH.mockResolvedValue(problem(412))
    const { wrapper, submit } = await mount('acl')
    await overrideToggle(wrapper, 'Allow lists').setValue(true)
    await submit()
    expect(wrapper.text()).toContain('changed by someone else')
  })

  it('is read-only for a viewer', async () => {
    const { wrapper } = await mount('acl', { me: viewerMe })
    expect(wrapper.text()).toContain('read-only access')
    expect(wrapper.findAll('button').map((b) => b.text())).not.toContain('Save')
    expect(overrideToggle(wrapper, 'Allow lists').element.disabled).toBe(true)
  })

  it('shows the matched ACL per source in the test box', async () => {
    const { wrapper } = await mount('acl')
    await control(wrapper, 'Path').setValue('/login')
    const forms = wrapper.findAll('form')
    await forms[forms.length - 1]?.trigger('submit')
    await flushPromises()
    const table = wrapper.get('[data-testid="effective-acl"]')
    const rows = table.findAll('tbody tr').map((r) => r.text())
    expect(rows.find((r) => r.startsWith('allow_lists'))).toContain('this site')
    expect(rows.find((r) => r.startsWith('country_mode'))).toContain('global defaults')
    expect(api.GET).toHaveBeenCalledWith('/sites/{site}/effective-policy', {
      params: { path: { site: 'shop' }, query: { path: '/login', method: 'GET' } },
    })
  })
})

describe('site rate limits tab', () => {
  it('lists inherited items with the audited opt-out note', async () => {
    const { wrapper } = await mount('rate-limits')
    const row = wrapper.get('[data-testid="inherited-global-per-ip"]')
    expect(row.text()).toContain('600 per 1m, by ip')
    expect(row.text()).toContain('Inherited from global defaults')
    expect(wrapper.text()).toContain('Opt-outs are recorded in the audit log')
  })

  it('writes opt_out for an inherited item', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
    const { wrapper, submit } = await mount('rate-limits')
    await wrapper
      .get('[data-testid="inherited-global-per-ip"] input[type="checkbox"]')
      .setValue(true)
    expect(wrapper.get('[data-testid="inherited-global-per-ip"]').text()).toContain('Opted out')
    await submit()
    expect(patch()[1].body).toEqual({ policy: { opt_out: ['rate_limits:global-per-ip'] } })
  })

  it('an item named like an inherited one overrides it', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
    const { wrapper, submit } = await mount('rate-limits')
    await buttonNamed(wrapper, 'Add rate limit').trigger('click')
    const editor = wrapper.get('[data-testid="rate-limit-editor"]')
    await control(wrapper, 'Name').setValue('global-per-ip')
    expect(editor.text()).toContain('replaces the item with the same name from global defaults')
    await control(wrapper, 'Paths').setValue('/api/*')
    await control(wrapper, 'Limit (requests)').setValue('100')
    await control(wrapper, 'Window').setValue('30s')
    expect(editor.text()).toContain('Challenge is currently enforced as a block')
    await buttonNamed(editor, 'Apply').trigger('click')
    const row = wrapper.get('[data-testid="own-global-per-ip"]')
    expect(row.text()).toContain('Overrides global defaults item')
    // The replaced inherited row is gone: one item with that name is shown.
    expect(wrapper.find('[data-testid="inherited-global-per-ip"]').exists()).toBe(false)
    await submit()
    expect(patch()[1].body).toEqual({
      policy: {
        rate_limits: [
          {
            name: 'global-per-ip',
            match: { paths: ['/api/*'] },
            key: 'ip',
            limit: 100,
            window: '30s',
            action: 'block',
          },
        ],
      },
    })
  })

  it('builds a header-keyed challenge item with methods', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
    const { wrapper, submit } = await mount('rate-limits')
    await buttonNamed(wrapper, 'Add rate limit').trigger('click')
    const editor = wrapper.get('[data-testid="rate-limit-editor"]')
    await control(wrapper, 'Name').setValue('api-key')
    await control(wrapper, 'Count requests per').setValue('header')
    await control(wrapper, 'Header name').setValue('X-Api-Key')
    await editor.get('input[type="checkbox"][value="POST"]').setValue(true)
    await control(wrapper, 'Limit (requests)').setValue('5')
    await control(wrapper, 'Action when exceeded').setValue('challenge')
    await buttonNamed(editor, 'Apply').trigger('click')
    await submit()
    expect(patch()[1].body).toEqual({
      policy: {
        rate_limits: [
          {
            name: 'api-key',
            match: { methods: ['POST'] },
            key: 'header:X-Api-Key',
            limit: 5,
            window: '1m',
            action: 'challenge',
          },
        ],
      },
    })
  })

  it('re-adding an opted-out name drops the opt-out so the server accepts it', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
    const { wrapper, submit } = await mount('rate-limits', {
      policy: { mode: 'detect', opt_out: ['rate_limits:login', 'other:thing'] },
    })
    await buttonNamed(wrapper, 'Add rate limit').trigger('click')
    const editor = wrapper.get('[data-testid="rate-limit-editor"]')
    await control(wrapper, 'Name').setValue('login')
    await control(wrapper, 'Limit (requests)').setValue('3')
    await buttonNamed(editor, 'Apply').trigger('click')
    await submit()
    expect(patch()[1].body).toEqual({
      policy: {
        rate_limits: [{ name: 'login', key: 'ip', limit: 3, window: '1m', action: 'block' }],
        opt_out: ['other:thing'],
      },
    })
  })

  it('validates an item before it is applied', async () => {
    const { wrapper } = await mount('rate-limits')
    await buttonNamed(wrapper, 'Add rate limit').trigger('click')
    const editor = wrapper.get('[data-testid="rate-limit-editor"]')
    await control(wrapper, 'Name').setValue('Bad Name')
    await control(wrapper, 'Window').setValue('soon')
    await control(wrapper, 'Paths').setValue('api/*')
    await buttonNamed(editor, 'Apply').trigger('click')
    expect(errorOf(wrapper, 'Name')).toContain('lowercase')
    expect(errorOf(wrapper, 'Limit (requests)')).toContain('whole number')
    expect(errorOf(wrapper, 'Window')).toContain('duration')
    expect(errorOf(wrapper, 'Paths')).toContain('Line 1')
    expect(wrapper.find('[data-testid="own-Bad Name"]').exists()).toBe(false)
  })

  it('removes an own item with a null merge-patch value', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
    const mine = { name: 'mine', limit: 1, window: '1m' }
    const { wrapper, submit } = await mount('rate-limits', {
      policy: { mode: 'detect', rate_limits: [mine] },
    })
    await wrapper.get('button[aria-label="Remove rate limit mine"]').trigger('click')
    await submit()
    expect(patch()[1].body).toEqual({ policy: { rate_limits: null } })
  })

  it('puts a per-item server error on its row', async () => {
    api.PATCH.mockResolvedValue(
      problem(422, {
        errors: [
          { path: '/sites/1/policy/rate_limits/0/limit', code: 'range', message: 'too high' },
          {
            path: '/sites/1/policy/opt_out/0',
            code: 'not_found',
            message: 'nothing to opt out of',
          },
        ],
      }),
    )
    const { wrapper, submit } = await mount('rate-limits', {
      policy: { mode: 'detect', rate_limits: [{ name: 'mine', limit: 9, window: '1m' }] },
    })
    await wrapper.get('[data-testid="inherited-login"] input[type="checkbox"]').setValue(true)
    await submit()
    expect(wrapper.text()).toContain('mine: too high')
    expect(wrapper.text()).toContain('Line 1: nothing to opt out of')
  })

  it('sets the per-site auto-ban fields and says endpoints are ignored', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
    const { wrapper, submit } = await mount('rate-limits')
    expect(wrapper.text()).toContain('values set on an endpoint are ignored')
    await overrideToggle(wrapper, 'Blocks before a ban').setValue(true)
    await control(wrapper, 'Blocks before a ban').setValue('20')
    await overrideToggle(wrapper, 'Ban duration').setValue(true)
    await control(wrapper, 'Ban duration').setValue('30m')
    await submit()
    expect(patch()[1].body).toEqual({
      policy: { auto_ban: { blocks_threshold: 20, ban_duration: '30m' } },
    })
  })

  it('is read-only for a viewer', async () => {
    const { wrapper } = await mount('rate-limits', { me: viewerMe })
    expect(wrapper.text()).toContain('read-only access')
    expect(wrapper.findAll('button').map((b) => b.text())).not.toContain('Add rate limit')
    const optOut = wrapper.get('[data-testid="inherited-global-per-ip"] input[type="checkbox"]')
    expect((optOut.element as HTMLInputElement).disabled).toBe(true)
  })

  it('shows the matching rate limits per source in the test box', async () => {
    const { wrapper } = await mount('rate-limits')
    const forms = wrapper.findAll('form')
    await forms[forms.length - 1]?.trigger('submit')
    await flushPromises()
    const limits = wrapper.get('[data-testid="effective-limits"]')
    expect(limits.text()).toContain('global-per-ip')
    expect(limits.text()).toContain('global defaults')
    const ban = wrapper.get('[data-testid="effective-auto-ban"]').text()
    expect(ban).toContain('5m')
    expect(ban).toContain('30m')
    expect(ban).toContain('this site')
  })
})
