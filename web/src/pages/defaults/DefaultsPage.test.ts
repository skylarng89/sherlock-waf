import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { control, errorOf, serve } from '@/pages/sites/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import DefaultsPage from './DefaultsPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

async function mountDefaults(
  me = adminMe,
  defaults = () => ok({ mode: 'detect', waf: { paranoia_level: 1 } }, { etag: '"v5"' }),
) {
  serve(api, {
    '/defaults': defaults,
    '/block-pages': () => ok({ items: [] }),
  })
  const view = await renderWithApp(DefaultsPage, { me, route: '/defaults' })
  const submit = async () => {
    await view.wrapper.get('form').trigger('submit')
    await flushPromises()
  }
  return { ...view, submit }
}

beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

describe('DefaultsPage', () => {
  it('loads the defaults into plain labelled fields', async () => {
    const { wrapper } = await mountDefaults()
    expect(wrapper.findAll('h1')).toHaveLength(1)
    expect((control(wrapper, 'Mode').element as HTMLSelectElement).value).toBe('detect')
    expect((control(wrapper, 'Paranoia level').element as HTMLInputElement).value).toBe('1')
  })

  it('saves with PUT /defaults and If-Match, omitting unset fields', async () => {
    api.PUT.mockResolvedValue(ok({}, { etag: '"v6"' }))
    const { wrapper, submit } = await mountDefaults()
    await control(wrapper, 'Paranoia level').setValue('2')
    await control(wrapper, 'Failure mode').setValue('closed')
    await submit()
    expect(api.PUT).toHaveBeenCalledWith('/defaults', {
      params: { header: { 'If-Match': '"v5"' } },
      body: { mode: 'detect', fail_mode: 'closed', waf: { paranoia_level: 2 } },
    })
  })

  it('maps /global/defaults/... pointers onto the fields', async () => {
    api.PUT.mockResolvedValue(
      problem(422, {
        errors: [
          { path: '/global/defaults/waf/paranoia_level', code: 'range', message: 'must be 1-4' },
          { path: '/global/defaults/bot/enabled', code: 'x', message: 'unknown field' },
        ],
      }),
    )
    const { wrapper, submit } = await mountDefaults()
    await control(wrapper, 'Paranoia level').setValue('9')
    await submit()
    expect(errorOf(wrapper, 'Paranoia level')).toBe('must be 1-4')
    expect(control(wrapper, 'Paranoia level').attributes('aria-invalid')).toBe('true')
    expect(wrapper.get('[role="alert"]').text()).toContain('bot.enabled: unknown field')
  })

  it('maps ACL and rate-limit pointers onto the access fields', async () => {
    api.PUT.mockResolvedValue(
      problem(422, {
        errors: [
          { path: '/global/defaults/acl/allow_lists/0', code: 'x', message: 'no such list' },
          { path: '/global/defaults/rate_limits/0/limit', code: 'range', message: 'too high' },
        ],
      }),
    )
    const { wrapper, submit } = await mountDefaults(adminMe, () =>
      ok({ rate_limits: [{ name: 'global', limit: 5, window: '1m' }] }, { etag: '"v5"' }),
    )
    await submit()
    expect(errorOf(wrapper, 'Allow lists')).toBe('Line 1: no such list')
    expect(wrapper.text()).toContain('too high')
  })

  it('offers a reload on 412', async () => {
    api.PUT.mockResolvedValue(problem(412))
    const { wrapper, submit } = await mountDefaults()
    await control(wrapper, 'Paranoia level').setValue('2')
    await submit()
    expect(wrapper.get('[role="alert"]').text()).toContain('changed by someone else')
  })

  it('starts empty when nothing is stored yet (404)', async () => {
    const { wrapper } = await mountDefaults(adminMe, () => problem(404))
    expect((control(wrapper, 'Mode').element as HTMLSelectElement).value).toBe('')
  })

  it('is read-only for viewers', async () => {
    const { wrapper } = await mountDefaults(viewerMe)
    expect(wrapper.text()).toContain('read-only access')
    expect(wrapper.find('button[type="submit"]').exists()).toBe(false)
    expect((control(wrapper, 'Mode').element as HTMLSelectElement).disabled).toBe(true)
  })

  it('shows an error state with retry when loading fails', async () => {
    const { wrapper } = await mountDefaults(adminMe, () => problem(500))
    expect(wrapper.get('[role="alert"]').text()).toContain('could not be loaded')
  })

  it('saves ACL lists, rate limits and auto-ban as plain fields', async () => {
    api.PUT.mockResolvedValue(ok({}, { etag: '"v6"' }))
    const { wrapper, submit } = await mountDefaults()
    expect(wrapper.find('[data-testid="acl-form"] [data-overridden]').exists()).toBe(false)
    const lists = control(wrapper, 'Allow lists')
    await lists.setValue('office')
    await lists.trigger('keydown.enter')
    await control(wrapper, 'Blocks before a ban').setValue('20')
    await Array.from(wrapper.findAll('button'))
      .find((b) => b.text() === 'Add rate limit')
      ?.trigger('click')
    await control(wrapper, 'Name').setValue('global-per-ip')
    await control(wrapper, 'Limit (requests)').setValue('600')
    await Array.from(wrapper.findAll('button'))
      .find((b) => b.text() === 'Apply')
      ?.trigger('click')
    await submit()
    expect(api.PUT).toHaveBeenCalledWith('/defaults', {
      params: { header: { 'If-Match': '"v5"' } },
      body: {
        mode: 'detect',
        waf: { paranoia_level: 1 },
        acl: { allow_lists: ['office'] },
        auto_ban: { blocks_threshold: 20 },
        rate_limits: [
          { name: 'global-per-ip', key: 'ip', limit: 600, window: '1m', action: 'block' },
        ],
      },
    })
  })
})
