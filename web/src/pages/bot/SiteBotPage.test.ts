import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'

import SiteBotPage from './SiteBotPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>
beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

const site = (bot?: object) => ({
  id: 'shop',
  name: 'Shop',
  hosts: ['shop.test'],
  upstreams: { targets: ['10.0.0.1:80'] },
  policy: { mode: 'block', ...(bot ? { bot } : {}) },
})

async function mount(me = adminMe, bot?: object) {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/sites') return ok({ items: [site(bot)] }, { etag: '"v3"' })
    if (path === '/defaults') return ok({})
    return problem(404)
  })
  return renderWithApp(SiteBotPage, { me, route: '/sites/shop/bot' })
}
const submit = async (w: Awaited<ReturnType<typeof mount>>['wrapper']) => {
  await w.get('form').trigger('submit')
  await flushPromises()
}
const field = (w: Awaited<ReturnType<typeof mount>>['wrapper'], label: string) => {
  const l = w.findAll('label').find((x) => x.text().startsWith(label))
  if (!l) throw new Error(`no label ${label}`)
  return w.get(`[id="${l.attributes('for')}"]`)
}

describe('site bot tab', () => {
  it('saves a merge patch with only the changed bot fields', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v4"' }))
    const { wrapper } = await mount(adminMe, { enabled: false, difficulty: 4 })
    await wrapper.get('input[type="checkbox"]').setValue(true)
    await field(wrapper, 'Difficulty').setValue('5')
    await submit(wrapper)
    const [path, init] = api.PATCH.mock.calls[0] as [string, { params: unknown; body: unknown }]
    expect(path).toBe('/sites/{site}')
    expect(init.params).toEqual({ path: { site: 'shop' }, header: { 'If-Match': '"v3"' } })
    expect(init.body).toEqual({ policy: { bot: { enabled: true, difficulty: 5 } } })
  })

  it('adds a rule and sends it as an array', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v4"' }))
    const { wrapper } = await mount(adminMe, { enabled: true })
    await wrapper
      .findAll('button')
      .find((b) => b.text().includes('Add rule'))
      ?.trigger('click')
    await field(wrapper, 'Paths').setValue('/login, /checkout')
    await field(wrapper, 'Methods').setValue('post')
    await submit(wrapper)
    const body = (api.PATCH.mock.calls[0] as [string, { body: unknown }])[1].body
    expect(body).toEqual({
      policy: {
        bot: {
          rules: [
            {
              match: { paths: ['/login', '/checkout'], methods: ['POST'] },
              action: 'challenge',
            },
          ],
        },
      },
    })
  })

  it('shows a server field error next to the field', async () => {
    api.PATCH.mockResolvedValue(
      problem(422, {
        errors: [{ path: '/sites/0/policy/bot/difficulty', code: 'range', message: 'Too high' }],
      }),
    )
    const { wrapper } = await mount(adminMe, { enabled: true, difficulty: 4 })
    await field(wrapper, 'Difficulty').setValue('40')
    await submit(wrapper)
    expect(field(wrapper, 'Difficulty').attributes('aria-invalid')).toBe('true')
    expect(wrapper.text()).toContain('Too high')
  })

  it('offers a reload on a stale write', async () => {
    api.PATCH.mockResolvedValue(problem(412))
    const { wrapper } = await mount(adminMe, { enabled: true, difficulty: 4 })
    await field(wrapper, 'Difficulty').setValue('6')
    await submit(wrapper)
    expect(wrapper.text()).toContain('changed by someone else')
  })

  it('is read-only for a viewer', async () => {
    const { wrapper } = await mount(viewerMe, { enabled: true })
    expect(wrapper.find('button[type="submit"]').exists()).toBe(false)
    expect(field(wrapper, 'Challenge type').attributes('disabled')).toBeDefined()
  })

  it('shows the provider site key for Turnstile instead of the difficulty', async () => {
    const { wrapper } = await mount(adminMe, { enabled: true, challenge: 'turnstile' })
    expect(wrapper.text()).toContain('Provider site key')
    expect(wrapper.text()).not.toContain('Difficulty')
  })
})
