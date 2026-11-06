import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import { control } from '@/pages/sites/testing'
import SiteLoginPage from './SiteLoginPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>
beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

const site = (policy: object = { mode: 'block' }) => ({
  id: 'bank',
  name: 'Bank',
  hosts: ['bank.test'],
  upstreams: { targets: ['10.0.0.1:80'] },
  policy,
})

async function mount(me = adminMe, policy?: object, defaults: object = {}) {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/sites') return ok({ items: [site(policy)] }, { etag: '"v3"' })
    if (path === '/defaults') return ok(defaults)
    return problem(404)
  })
  return renderWithApp(SiteLoginPage, { me, route: '/sites/bank/login-protection' })
}
const submit = async (w: Awaited<ReturnType<typeof mount>>['wrapper']) => {
  await w.get('form').trigger('submit')
  await flushPromises()
}
const click = async (w: Awaited<ReturnType<typeof mount>>['wrapper'], text: string) => {
  await w
    .findAll('button')
    .find((b) => b.text().includes(text))
    ?.trigger('click')
  await flushPromises()
}

describe('site login protection tab', () => {
  it('states the privacy promise and shows inherited values', async () => {
    const { wrapper } = await mount(
      adminMe,
      { mode: 'block' },
      {
        login_protection: { thresholds: { per_username: 3, window: '30m' }, action: 'block' },
      },
    )
    expect(wrapper.get('[data-testid="login-privacy"]').text()).toContain('keyed hash')
    expect(wrapper.text()).toContain('Inherited: 3')
    expect(wrapper.text()).toContain('Inherited: 30m')
    expect(wrapper.text()).toContain('Inherited: block')
    expect(wrapper.text()).toContain('Default: 20')
  })

  it('warns in detect mode that findings are recorded but not enforced', async () => {
    const { wrapper } = await mount(adminMe, { mode: 'detect' })
    expect(wrapper.get('[data-testid="mode-notice"]').text()).toContain('recorded but not enforced')
    const block = await mount(adminMe, { mode: 'block' })
    expect(block.wrapper.find('[data-testid="mode-notice"]').exists()).toBe(false)
  })

  it('warns when enabled with no endpoint declared', async () => {
    const { wrapper } = await mount(adminMe, { mode: 'block', login_protection: { enabled: true } })
    expect(wrapper.get('[data-testid="no-endpoints"]').text()).toContain('nothing is watched')
  })

  it('saves a merge patch with an endpoint and the thresholds', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v4"' }))
    const { wrapper } = await mount()
    await click(wrapper, 'Add endpoint')
    const ep = wrapper.get('[data-testid="login-endpoint-0"]')
    await ep.findAll('input[type="text"]')[1]?.setValue('email')
    await ep.findAll('input[type="text"]')[2]?.setValue('401, 422')
    await control(wrapper, 'Failures per client address').setValue('30')
    await control(wrapper, 'Window').setValue('15m')
    await submit(wrapper)
    const [path, init] = api.PATCH.mock.calls[0] as [
      string,
      { params: unknown; body: { policy: { login_protection: Record<string, unknown> } } },
    ]
    expect(path).toBe('/sites/{site}')
    expect(init.params).toEqual({ path: { site: 'bank' }, header: { 'If-Match': '"v3"' } })
    expect(init.body.policy.login_protection).toEqual({
      endpoints: [{ path: '/login', username_field: 'email', failure_statuses: [401, 422] }],
      thresholds: { per_ip: 30, window: '15m' },
    })
  })

  it('refuses invalid input without calling the API and announces the errors on the fields', async () => {
    const { wrapper } = await mount()
    await click(wrapper, 'Add endpoint')
    await control(wrapper, 'Failures per username').setValue('0')
    await submit(wrapper)
    expect(api.PATCH).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('Name the form field or JSON pointer')
    expect(wrapper.text()).toContain('whole number from 1 to 100000')
    const field = control(wrapper, 'Failures per username')
    expect(field.attributes('aria-invalid')).toBe('true')
  })

  it('puts a server refusal on the path field of the endpoint', async () => {
    api.PATCH.mockResolvedValue(
      problem(422, {
        errors: [
          {
            path: '/sites/0/policy/login_protection/endpoints/0/path',
            code: 'invalid',
            message: 'must start with /',
          },
        ],
      }),
    )
    const { wrapper } = await mount(adminMe, {
      mode: 'block',
      login_protection: { endpoints: [{ path: '/login', username_field: 'u' }] },
    })
    await control(wrapper, 'Failures per client address').setValue('25')
    await submit(wrapper)
    expect(wrapper.text()).toContain('must start with /')
    expect(wrapper.text()).not.toContain('Line 1')
    expect(control(wrapper, 'Path').attributes('aria-describedby')).toContain('-error')
  })

  it('is read-only without config:write', async () => {
    const { wrapper } = await mount(viewerMe, {
      mode: 'block',
      login_protection: { enabled: true },
    })
    expect(wrapper.text()).toContain('You can view this policy but not change it.')
    expect(wrapper.findAll('button[type="submit"]')).toHaveLength(0)
    expect(wrapper.text()).not.toContain('Add endpoint')
  })
})

describe('Fintech baseline panel', () => {
  it('shows the diff, a mode hint and an endpoint prompt, then applies only what is new', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v4"' }))
    const { wrapper } = await mount(adminMe, {
      mode: 'detect',
      login_protection: { thresholds: { per_ip: 100 } },
    })
    await click(wrapper, 'Review baseline')
    expect(wrapper.get('[data-testid="fintech-mode-hint"]').text()).toContain('detect mode')
    expect(wrapper.get('[data-testid="fintech-endpoints-prompt"]').text()).toContain(
      'Login protection stays inactive',
    )
    const table = wrapper.get('[data-testid="fintech-diff"]').text()
    expect(table).toContain('Kept (yours differs)')
    expect(table).toContain('Will be set')

    await click(wrapper, 'Apply baseline')
    const [, init] = api.PATCH.mock.calls[0] as [
      string,
      { body: { policy: Record<string, Record<string, unknown>> } },
    ]
    expect(init.body.policy).not.toHaveProperty('mode')
    expect(init.body.policy.login_protection).toMatchObject({ enabled: true, action: 'challenge' })
    expect(init.body.policy.login_protection?.thresholds).not.toHaveProperty('per_ip')
    expect(init.body.policy.dlp).toEqual({ enabled: true, detect: ['pan', 'iban'], action: 'mask' })
    expect(init.body.policy.bot).toEqual({ enabled: true, challenge: 'pow' })
  })

  it('replaces a differing value only after an explicit opt-in', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v4"' }))
    const { wrapper } = await mount(adminMe, {
      mode: 'block',
      login_protection: { thresholds: { per_ip: 100 } },
    })
    await click(wrapper, 'Review baseline')
    await wrapper
      .findAll('input[type="checkbox"]')
      .find((i) =>
        i.element.closest('td')?.textContent?.includes('Login failures per client address'),
      )
      ?.setValue(true)
    await click(wrapper, 'Apply baseline')
    const [, init] = api.PATCH.mock.calls[0] as [
      string,
      { body: { policy: { login_protection: { thresholds: { per_ip: number } } } } },
    ]
    expect(init.body.policy.login_protection.thresholds.per_ip).toBe(20)
  })

  it('cannot be applied by a read-only user', async () => {
    const { wrapper } = await mount(viewerMe, { mode: 'block' })
    await click(wrapper, 'Review baseline')
    expect(wrapper.text()).toContain('review the baseline but not apply it')
    expect(wrapper.text()).not.toContain('Apply baseline')
  })
})
