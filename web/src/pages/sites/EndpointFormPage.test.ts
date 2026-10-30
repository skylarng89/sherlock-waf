import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import EndpointFormPage from './EndpointFormPage.vue'
import { blog, control, errorOf, overrideToggle, serve, shop } from './testing'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

async function mountForm(route: string, me = adminMe) {
  serve(api, {
    '/sites': () => ok({ items: [blog, shop] }, { etag: '"v7"' }),
    '/defaults': () => ok({ waf: { inbound_threshold: 5 } }),
    '/certificates': () => ok({ items: [] }),
    '/block-pages': () => ok({ items: [] }),
  })
  const view = await renderWithApp(EndpointFormPage, { me, route })
  const submit = async () => {
    await view.wrapper.get('form').trigger('submit')
    await flushPromises()
  }
  return { ...view, submit }
}

beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

describe('EndpointFormPage', () => {
  describe('inheritance display (SkInheritedField)', () => {
    it('shows each inherited value greyed with the level it comes from', async () => {
      const { wrapper } = await mountForm('/sites/shop/endpoints/new')
      const rows = wrapper.findAll('[data-testid="policy-form"] [data-overridden]')
      expect(rows.length).toBeGreaterThan(8)
      expect(rows.every((r) => r.attributes('data-overridden') === 'false')).toBe(true)
      const text = (label: string) => {
        const id = control(wrapper, label).attributes('id')
        return wrapper.get(`[id="${id}"]`).element.closest('[data-overridden]')?.textContent ?? ''
      }
      // Set on the site -> "this site"; set only in defaults -> "global defaults"; nowhere -> built-in.
      expect(text('Mode')).toContain('Inherited from this site')
      expect(text('Mode')).toContain('Detect')
      expect(text('Paranoia level')).toContain('Inherited from this site')
      expect(text('Inbound anomaly threshold')).toContain('Inherited from global defaults')
      expect(text('Inbound anomaly threshold')).toContain('5')
      expect(text('Failure mode')).toContain('Inherited from built-in default')
      expect(text('Failure mode')).toContain('not set')
      // Inherited values are output text, not editable controls.
      expect(control(wrapper, 'Mode').element.tagName).toBe('OUTPUT')
    })

    it('reveals an editor on Override and says what it overrides; undoing restores inheritance', async () => {
      const { wrapper } = await mountForm('/sites/shop/endpoints/new')
      const toggle = overrideToggle(wrapper, 'Paranoia level')
      expect(toggle.attributes('role')).toBe('switch')
      await toggle.setValue(true)
      const input = control(wrapper, 'Paranoia level')
      expect(input.element.tagName).toBe('INPUT')
      expect((input.element as HTMLInputElement).value).toBe('1')
      expect(input.element.closest('[data-overridden]')?.textContent).toContain(
        'Overrides this site: 1',
      )
      await toggle.setValue(false)
      expect(control(wrapper, 'Paranoia level').element.tagName).toBe('OUTPUT')
    })
  })

  it('creates an endpoint with only the overridden fields, using If-Match', async () => {
    api.POST.mockResolvedValue(ok({}, { status: 201, etag: '"v8"' }))
    const { wrapper, submit, router } = await mountForm('/sites/shop/endpoints/new')
    await control(wrapper, 'Endpoint ID').setValue('upload')
    await control(wrapper, 'Match type').setValue('path_prefix')
    await control(wrapper, 'Path').setValue('/upload/')
    await wrapper.get('input[type="checkbox"][value="POST"]').setValue(true)
    await overrideToggle(wrapper, 'Mode').setValue(true)
    await control(wrapper, 'Mode').setValue('block')
    await submit()
    expect(api.POST).toHaveBeenCalledWith('/sites/{site}/endpoints', {
      params: { path: { site: 'shop' }, header: { 'If-Match': '"v7"' } },
      body: {
        id: 'upload',
        match: { path_prefix: '/upload/', methods: ['POST'] },
        policy: { mode: 'block' },
      },
    })
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('site-endpoints'))
  })

  it('validates id and path locally', async () => {
    const { wrapper, submit } = await mountForm('/sites/shop/endpoints/new')
    await submit()
    expect(api.POST).not.toHaveBeenCalled()
    expect(errorOf(wrapper, 'Endpoint ID')).toContain('lowercase')
    expect(errorOf(wrapper, 'Path')).toContain('Enter the path')
  })

  it('shows a duplicate endpoint id (409) on the id field', async () => {
    api.POST.mockResolvedValue(problem(409))
    const { wrapper, submit } = await mountForm('/sites/shop/endpoints/new')
    await control(wrapper, 'Endpoint ID').setValue('login')
    await control(wrapper, 'Path').setValue('/x')
    await submit()
    expect(errorOf(wrapper, 'Endpoint ID')).toContain('already exists')
  })

  describe('editing', () => {
    it('loads the existing overrides and PATCHes only the difference', async () => {
      api.PATCH.mockResolvedValue(ok({}, { etag: '"v8"' }))
      const { wrapper, submit } = await mountForm('/sites/shop/endpoints/login')
      expect((control(wrapper, 'Endpoint ID').element as HTMLInputElement).disabled).toBe(true)
      expect((control(wrapper, 'Path').element as HTMLInputElement).value).toBe('/login')
      // The paranoia override is active and states what it overrides.
      const row = control(wrapper, 'Paranoia level').element.closest('[data-overridden]')
      expect(row?.getAttribute('data-overridden')).toBe('true')
      expect(row?.textContent).toContain('Overrides this site: 1')
      await control(wrapper, 'Paranoia level').setValue('3')
      await submit()
      expect(api.PATCH).toHaveBeenCalledWith('/sites/{site}/endpoints/{endpoint}', {
        params: { path: { site: 'shop', endpoint: 'login' }, header: { 'If-Match': '"v7"' } },
        headers: { 'Content-Type': 'application/merge-patch+json' },
        body: { policy: { waf: { paranoia_level: 3 } } },
      })
    })

    it('maps /sites/1/endpoints/0/... errors to the endpoint form fields', async () => {
      api.PATCH.mockResolvedValue(
        problem(422, {
          errors: [
            { path: '/sites/1/endpoints/0/match/path', code: 'x', message: 'must start with /' },
            { path: '/sites/1/endpoints/0/match/methods/0', code: 'x', message: 'unknown method' },
            {
              path: '/sites/1/endpoints/0/policy/waf/paranoia_level',
              code: 'range',
              message: 'must be 1-4',
            },
            { path: '/sites/1/endpoints/0/id', code: 'x', message: 'id problem' },
          ],
        }),
      )
      const { wrapper, submit } = await mountForm('/sites/shop/endpoints/login')
      await control(wrapper, 'Paranoia level').setValue('9')
      await submit()
      expect(errorOf(wrapper, 'Path')).toBe('must start with /')
      expect(control(wrapper, 'Path').attributes('aria-invalid')).toBe('true')
      expect(wrapper.get('#methods-error').text()).toContain('unknown method')
      expect(errorOf(wrapper, 'Paranoia level')).toBe('must be 1-4')
      expect(errorOf(wrapper, 'Endpoint ID')).toBe('id problem')
    })

    it('offers a reload on 412', async () => {
      api.PATCH.mockResolvedValue(problem(412))
      const { wrapper, submit } = await mountForm('/sites/shop/endpoints/login')
      await control(wrapper, 'Paranoia level').setValue('3')
      await submit()
      expect(wrapper.get('[role="alert"]').text()).toContain('changed by someone else')
    })

    it('is read-only for viewers', async () => {
      const { wrapper } = await mountForm('/sites/shop/endpoints/login', viewerMe)
      expect(wrapper.text()).toContain('read-only access')
      expect(
        wrapper.findAll('button[type="submit"]').filter((b) => !b.element.closest('dialog')),
      ).toHaveLength(0)
      expect(overrideToggle(wrapper, 'Paranoia level').attributes('disabled')).toBeDefined()
    })

    it('reports an unknown endpoint', async () => {
      const { wrapper } = await mountForm('/sites/shop/endpoints/ghost')
      expect(wrapper.get('[role="alert"]').text()).toContain('does not exist')
    })
  })

  describe('access control sections', () => {
    async function mountWithLimits() {
      serve(api, {
        '/sites': () => ok({ items: [blog, shop] }, { etag: '"v7"' }),
        '/defaults': () =>
          ok({
            acl: { deny_lists: ['known-bad'] },
            rate_limits: [{ name: 'global-per-ip', limit: 600, window: '1m' }],
          }),
        '/certificates': () => ok({ items: [] }),
        '/block-pages': () => ok({ items: [] }),
      })
      const view = await renderWithApp(EndpointFormPage, {
        me: adminMe,
        route: '/sites/shop/endpoints/new',
      })
      return view
    }

    it('shows inherited ACL and rate limits and sends edits and opt-outs in the policy', async () => {
      api.POST.mockResolvedValue(ok({}, { status: 201, etag: '"v8"' }))
      const { wrapper } = await mountWithLimits()
      expect(wrapper.get('[data-testid="inherited-global-per-ip"]').text()).toContain(
        'Inherited from global defaults',
      )
      await control(wrapper, 'Endpoint ID').setValue('health')
      await control(wrapper, 'Path').setValue('/healthz')
      await overrideToggle(wrapper, 'Deny lists').setValue(true)
      await wrapper.get('input[type="radio"][value="edit"]').setValue(true)
      const input = control(wrapper, 'Deny lists')
      await input.setValue('scanners')
      await input.trigger('keydown.enter')
      await wrapper
        .get('[data-testid="inherited-global-per-ip"] input[type="checkbox"]')
        .setValue(true)
      expect(wrapper.text()).toContain('values set on an endpoint are ignored')
      await wrapper.get('form').trigger('submit')
      await flushPromises()
      expect(api.POST).toHaveBeenCalledWith('/sites/{site}/endpoints', {
        params: { path: { site: 'shop' }, header: { 'If-Match': '"v7"' } },
        body: {
          id: 'health',
          match: { path_prefix: '/healthz' },
          policy: {
            acl: { deny_lists: { add: ['scanners'] } },
            opt_out: ['rate_limits:global-per-ip'],
          },
        },
      })
    })
  })
})
