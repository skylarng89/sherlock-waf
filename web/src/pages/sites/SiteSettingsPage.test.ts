import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import SiteSettingsPage from './SiteSettingsPage.vue'
import { blog, buttonNamed, control, dialogWithTitle, errorOf, serve, shop } from './testing'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

async function mountSettings(me = adminMe) {
  serve(api, {
    '/sites': () => ok({ items: [blog, shop] }, { etag: '"v7"' }),
    '/defaults': () => ok({ mode: 'detect', waf: { inbound_threshold: 5 } }),
    '/certificates': () => ok({ items: [] }),
    '/block-pages': () => ok({ items: [] }),
  })
  const view = await renderWithApp(SiteSettingsPage, { me, route: '/sites/shop' })
  const submit = async () => {
    await view.wrapper.get('form').trigger('submit')
    await flushPromises()
  }
  return { ...view, submit }
}

const patchCall = () =>
  api.PATCH.mock.calls[0] as [string, { params: unknown; headers: unknown; body: unknown }]

beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

describe('SiteSettingsPage', () => {
  it('shows every loaded field, with the id fixed', async () => {
    const { wrapper } = await mountSettings()
    expect(wrapper.get('h1').text()).toBe('Shop')
    expect((control(wrapper, 'Hostnames').element as HTMLTextAreaElement).value).toBe(
      'shop.example.com',
    )
    const id = control(wrapper, 'Site ID').element as HTMLInputElement
    expect(id.value).toBe('shop')
    expect(id.disabled).toBe(true)
    expect((control(wrapper, 'Upstream targets').element as HTMLTextAreaElement).value).toBe(
      '10.0.1.10:8080',
    )
    // Inherited-from-defaults display: the threshold is not set on the site.
    expect(wrapper.text()).toContain('Inherited from global defaults')
  })

  it('PATCHes only the changed fields with the ETag as If-Match', async () => {
    api.PATCH.mockResolvedValue(ok({ id: 'v8' }, { etag: '"v8"' }))
    const { wrapper, submit } = await mountSettings()
    await control(wrapper, 'Display name').setValue('Shop frontend')
    await submit()
    const [path, init] = patchCall()
    expect(path).toBe('/sites/{site}')
    expect(init.params).toEqual({ path: { site: 'shop' }, header: { 'If-Match': '"v7"' } })
    expect(init.headers).toEqual({ 'Content-Type': 'application/merge-patch+json' })
    expect(init.body).toEqual({ name: 'Shop frontend' })

    // The response ETag is used for the next write.
    await control(wrapper, 'Display name').setValue('Shop frontend 2')
    await submit()
    expect((api.PATCH.mock.calls[1] as [string, { params: unknown }])[1].params).toEqual({
      path: { site: 'shop' },
      header: { 'If-Match': '"v8"' },
    })
  })

  it('sends null for a cleared optional field', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
    const { wrapper, submit } = await mountSettings()
    await control(wrapper, 'Display name').setValue('')
    await submit()
    expect(patchCall()[1].body).toEqual({ name: null })
  })

  it('does not call the server when nothing changed', async () => {
    const { submit } = await mountSettings()
    await submit()
    expect(api.PATCH).not.toHaveBeenCalled()
  })

  it('offers a reload on 412 and reloads the site', async () => {
    api.PATCH.mockResolvedValue(problem(412))
    const { wrapper, submit } = await mountSettings()
    await control(wrapper, 'Display name').setValue('x')
    await submit()
    const alert = wrapper.get('[role="alert"]')
    expect(alert.text()).toContain('changed by someone else')
    api.GET.mockClear()
    await alert.get('button').trigger('click')
    await flushPromises()
    expect(api.GET).toHaveBeenCalledWith('/sites')
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
  })

  it('explains a missing version (428)', async () => {
    api.PATCH.mockResolvedValue(problem(428))
    const { wrapper, submit } = await mountSettings()
    await control(wrapper, 'Display name').setValue('x')
    await submit()
    expect(wrapper.get('[role="alert"]').text()).toContain('missing its version')
  })

  it('maps /sites/1/... pointers to the right fields and lists the rest', async () => {
    api.PATCH.mockResolvedValue(
      problem(422, {
        errors: [
          { path: '/sites/1/hosts/0', code: 'invalid_host', message: 'not a hostname' },
          { path: '/sites/1/policy/waf/paranoia_level', code: 'range', message: 'must be 1-4' },
          { path: '/sites/1/upstreams/timeouts/dial', code: 'duration', message: 'bad duration' },
          { path: '/sites/1/headers/x', code: 'unknown_field', message: 'unknown header block' },
        ],
      }),
    )
    const { wrapper, submit } = await mountSettings()
    await control(wrapper, 'Display name').setValue('x')
    await submit()
    expect(errorOf(wrapper, 'Hostnames')).toBe('Line 1: not a hostname')
    expect(control(wrapper, 'Hostnames').attributes('aria-invalid')).toBe('true')
    expect(errorOf(wrapper, 'Paranoia level')).toBe('must be 1-4')
    expect(errorOf(wrapper, 'Dial timeout')).toBe('bad duration')
    expect(wrapper.get('[role="alert"]').text()).toContain('unknown header block')
  })

  it('clears a field error when the user edits that field', async () => {
    api.PATCH.mockResolvedValue(
      problem(422, { errors: [{ path: '/sites/1/name', code: 'x', message: 'too long' }] }),
    )
    const { wrapper, submit } = await mountSettings()
    await control(wrapper, 'Display name').setValue('x')
    await submit()
    expect(errorOf(wrapper, 'Display name')).toBe('too long')
    await control(wrapper, 'Display name').setValue('y')
    expect(errorOf(wrapper, 'Display name')).toBe('')
  })

  describe('viewer', () => {
    it('is read-only: no save, mode switcher or delete, fields disabled', async () => {
      const { wrapper } = await mountSettings(viewerMe)
      expect(wrapper.text()).toContain('read-only access')
      const pageSubmits = wrapper
        .findAll('button[type="submit"]')
        .filter((b) => !b.element.closest('dialog'))
      expect(pageSubmits).toHaveLength(0)
      expect(wrapper.find('#mode-switcher').exists()).toBe(false)
      expect(wrapper.text()).not.toContain('Delete site')
      expect(wrapper.findAll('fieldset[disabled]').length).toBeGreaterThan(0)
      expect(
        wrapper
          .findAll('input[role="switch"]')
          .every((i) => i.attributes('disabled') !== undefined),
      ).toBe(true)
    })
  })

  describe('mode switcher', () => {
    it('asks for confirmation before switching to block, and only then PATCHes', async () => {
      api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
      const { wrapper } = await mountSettings()
      await wrapper.get('#mode-switcher').setValue('block')
      const dialog = dialogWithTitle(wrapper, 'Switch Shop to block mode?')
      expect(dialog.element.open).toBe(true)
      expect(dialog.text()).toContain('block page')
      expect(dialog.text()).toContain('would-block')
      expect(api.PATCH).not.toHaveBeenCalled()
      await buttonNamed(dialog, 'Switch to block').trigger('click')
      await dialog.get('form').trigger('submit')
      await flushPromises()
      expect(patchCall()[1].body).toEqual({ policy: { mode: 'block' } })
      expect(wrapper.get('[aria-label="Enforcement mode"]').text()).toContain('Block')
    })

    it('does not PATCH when the confirmation is cancelled', async () => {
      const { wrapper } = await mountSettings()
      await wrapper.get('#mode-switcher').setValue('block')
      const dialog = dialogWithTitle(wrapper, 'Switch Shop to block mode?')
      await buttonNamed(dialog, 'Cancel').trigger('click')
      await flushPromises()
      expect(api.PATCH).not.toHaveBeenCalled()
      expect(dialog.element.open).toBe(false)
    })

    it('switches to off without a dialog', async () => {
      api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
      const { wrapper } = await mountSettings()
      await wrapper.get('#mode-switcher').setValue('off')
      await flushPromises()
      expect(patchCall()[1].body).toEqual({ policy: { mode: 'off' } })
    })

    it('confirms when the form itself sets the policy mode to block', async () => {
      api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
      const { wrapper, submit } = await mountSettings()
      await control(wrapper, 'Mode').setValue('block')
      await submit()
      expect(api.PATCH).not.toHaveBeenCalled()
      const dialog = dialogWithTitle(wrapper, 'block mode')
      expect(dialog.element.open).toBe(true)
      await dialog.get('form').trigger('submit')
      await flushPromises()
      expect(patchCall()[1].body).toEqual({ policy: { mode: 'block' } })
    })
  })

  describe('delete', () => {
    it('requires typing the site id, then DELETEs with If-Match and returns to the list', async () => {
      api.DELETE.mockResolvedValue(ok({}, { etag: '"v8"' }))
      const { wrapper, router } = await mountSettings()
      await buttonNamed(wrapper, 'Delete site').trigger('click')
      const dialog = dialogWithTitle(wrapper, 'Delete shop?')
      expect(dialog.element.open).toBe(true)
      const confirm = dialog.get('button[type="submit"]')
      expect(confirm.attributes('disabled')).toBeDefined()
      await dialog.get('input[type="text"]').setValue('sho')
      expect(confirm.attributes('disabled')).toBeDefined()
      await dialog.get('input[type="text"]').setValue('shop')
      expect(confirm.attributes('disabled')).toBeUndefined()
      await dialog.get('form').trigger('submit')
      await flushPromises()
      expect(api.DELETE).toHaveBeenCalledWith('/sites/{site}', {
        params: { path: { site: 'shop' }, header: { 'If-Match': '"v7"' } },
      })
      await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('sites'))
    })

    it('shows the stale banner when the delete loses the race', async () => {
      api.DELETE.mockResolvedValue(problem(412))
      const { wrapper } = await mountSettings()
      await buttonNamed(wrapper, 'Delete site').trigger('click')
      const dialog = dialogWithTitle(wrapper, 'Delete shop?')
      await dialog.get('input[type="text"]').setValue('shop')
      await dialog.get('form').trigger('submit')
      await flushPromises()
      expect(wrapper.get('[role="alert"]').text()).toContain('changed by someone else')
    })
  })

  it('reports an unknown site', async () => {
    serve(api, {
      '/sites': () => ok({ items: [blog] }, { etag: '"v7"' }),
      '/defaults': () => ok({}),
    })
    const { wrapper } = await renderWithApp(SiteSettingsPage, { me: adminMe, route: '/sites/nope' })
    expect(wrapper.get('[role="alert"]').text()).toContain('does not exist')
  })
})
