import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { buttonNamed, control, errorOf } from '@/pages/sites/testing'
import { adminMe, renderWithApp } from '@/test-utils'
import SetupContinuePage from './SetupContinuePage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

async function mountContinue() {
  const view = await renderWithApp(SetupContinuePage, { me: adminMe, route: '/welcome' })
  const submit = async () => {
    await view.wrapper.get('form').trigger('submit')
    await flushPromises()
  }
  const toStep3 = async () => {
    await buttonNamed(view.wrapper, 'Skip this step').trigger('click')
    await flushPromises()
  }
  return { ...view, submit, toStep3 }
}

const freshNode = () => api.GET.mockResolvedValue(problem(404))
const existingConfig = () =>
  api.GET.mockResolvedValue(
    ok(
      {
        schema_version: 1,
        sites: [{ id: 'blog', hosts: ['b.example.com'], upstreams: { targets: ['x:1'] } }],
      },
      { etag: '"v2"' },
    ),
  )

beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

describe('SetupContinuePage', () => {
  describe('step 2: admin hostname', () => {
    it('explains DNS and port requirements and announces the step', async () => {
      const { wrapper } = await mountContinue()
      expect(wrapper.text()).toContain('Ports 80 and 443')
      expect(wrapper.text()).toContain('DNS')
      expect(wrapper.get('[aria-current="step"]').text()).toContain('Admin hostname')
      expect(wrapper.get('nav [role="status"]').text()).toBe('Step 2 of 4: Admin hostname')
      expect(wrapper.findAll('li').filter((l) => l.text().includes('completed'))).toHaveLength(1)
      expect((control(wrapper, 'Control plane address').element as HTMLInputElement).value).toBe(
        '127.0.0.1:9443',
      )
    })

    it('can be skipped without writing anything', async () => {
      const { wrapper, toStep3 } = await mountContinue()
      await toStep3()
      expect(api.PUT).not.toHaveBeenCalled()
      expect(api.POST).not.toHaveBeenCalled()
      expect(wrapper.get('[aria-current="step"]').text()).toContain('First site')
      expect(document.activeElement?.textContent).toContain('Add your first site')
    })

    it('creates the sherlock-admin site with PUT /config and no If-Match on a fresh node', async () => {
      freshNode()
      api.PUT.mockResolvedValue(ok({ id: 'v1' }, { etag: '"v1"' }))
      const { wrapper, submit } = await mountContinue()
      await control(wrapper, 'Admin hostname').setValue('waf.example.com')
      await submit()
      const [path, init] = api.PUT.mock.calls[0] as [
        string,
        { params: { header: object }; body: { sites: unknown[] } },
      ]
      expect(path).toBe('/config')
      expect(init.params.header).toEqual({})
      expect(init.body).toEqual({
        schema_version: 1,
        sites: [
          {
            id: 'sherlock-admin',
            name: 'Sherlock admin',
            hosts: ['waf.example.com'],
            tls: { mode: 'acme' },
            upstreams: {
              targets: ['127.0.0.1:9443'],
              tls: { enabled: true, insecure_skip_verify: true },
            },
            policy: { mode: 'detect' },
          },
        ],
      })
      expect(wrapper.get('[aria-current="step"]').text()).toContain('First site')
    })

    it('uses POST /sites with If-Match when a configuration already exists', async () => {
      existingConfig()
      api.POST.mockResolvedValue(ok({}, { status: 201 }))
      const { wrapper, submit } = await mountContinue()
      await control(wrapper, 'Admin hostname').setValue('waf.example.com')
      await submit()
      expect(api.PUT).not.toHaveBeenCalled()
      expect(api.POST).toHaveBeenCalledWith(
        '/sites',
        expect.objectContaining({
          params: { header: { 'If-Match': '"v2"' } },
          body: expect.objectContaining({ id: 'sherlock-admin' }),
        }),
      )
    })

    it('requires a hostname when not skipping', async () => {
      const { wrapper, submit } = await mountContinue()
      await submit()
      expect(errorOf(wrapper, 'Admin hostname')).toContain('Enter the hostname')
      expect(api.PUT).not.toHaveBeenCalled()
    })

    it('puts a server field error (rebased from /sites/1/hosts/0) on the hostname field', async () => {
      existingConfig()
      api.POST.mockResolvedValue(
        problem(422, {
          errors: [{ path: '/sites/1/hosts/0', code: 'x', message: 'not a hostname' }],
        }),
      )
      const { wrapper, submit } = await mountContinue()
      await control(wrapper, 'Admin hostname').setValue('not a host')
      await submit()
      expect(errorOf(wrapper, 'Admin hostname')).toBe('Line 1: not a hostname')
      expect(wrapper.get('[aria-current="step"]').text()).toContain('Admin hostname')
    })

    it('continues when the admin site already exists (409)', async () => {
      existingConfig()
      api.POST.mockResolvedValue(problem(409))
      const { wrapper, submit } = await mountContinue()
      await control(wrapper, 'Admin hostname').setValue('waf.example.com')
      await submit()
      expect(wrapper.get('[aria-current="step"]').text()).toContain('First site')
    })
  })

  describe('step 3: first site', () => {
    async function fillSite(wrapper: Awaited<ReturnType<typeof mountContinue>>['wrapper']) {
      await control(wrapper, 'Display name').setValue('My Shop')
      await control(wrapper, 'Public hostname').setValue('shop.example.com')
      await control(wrapper, 'Upstream address').setValue('10.0.1.10:8080')
    }

    it('derives the site id from the name until the user edits it', async () => {
      const { wrapper, toStep3 } = await mountContinue()
      await toStep3()
      await control(wrapper, 'Display name').setValue('My Shop')
      expect((control(wrapper, 'Site ID').element as HTMLInputElement).value).toBe('my-shop')
      await control(wrapper, 'Site ID').setValue('custom')
      await control(wrapper, 'Display name').setValue('Other')
      expect((control(wrapper, 'Site ID').element as HTMLInputElement).value).toBe('custom')
    })

    it('tests connectivity and shows status and latency', async () => {
      api.POST.mockResolvedValue(ok({ reachable: true, status: 200, latency_ms: 12 }))
      const { wrapper, toStep3 } = await mountContinue()
      await toStep3()
      await fillSite(wrapper)
      await buttonNamed(wrapper, 'Test connection').trigger('click')
      await flushPromises()
      expect(api.POST).toHaveBeenCalledWith('/system/test-upstream', {
        body: { target: '10.0.1.10:8080', tls: false, tls_skip_verify: false },
      })
      expect(wrapper.get('[data-testid="test-ok"]').text()).toContain('answered HTTP 200 in 12 ms')
    })

    it.each([
      ['dns', 'could not be resolved'],
      ['refused', 'connection was refused'],
      ['timeout', 'timed out'],
      ['tls', 'TLS handshake failed'],
      ['protocol', 'not with valid HTTP'],
    ])('explains the %s failure class in plain language', async (cls, text) => {
      api.POST.mockResolvedValue(ok({ reachable: false, latency_ms: 3000, error: cls }))
      const { wrapper, toStep3 } = await mountContinue()
      await toStep3()
      await fillSite(wrapper)
      await buttonNamed(wrapper, 'Test connection').trigger('click')
      await flushPromises()
      expect(wrapper.get('[data-testid="test-fail"]').text()).toContain(text)
      expect(wrapper.get('[data-testid="test-fail"]').attributes('role')).toBe('alert')
    })

    it('asks for an address before testing', async () => {
      const { wrapper, toStep3 } = await mountContinue()
      await toStep3()
      await buttonNamed(wrapper, 'Test connection').trigger('click')
      await flushPromises()
      expect(api.POST).not.toHaveBeenCalled()
      expect(wrapper.text()).toContain('Enter the upstream address first')
    })

    it('creates the site in detect mode and finishes with the explanation and a link', async () => {
      freshNode()
      api.PUT.mockResolvedValue(ok({}, { etag: '"v1"' }))
      const { wrapper, submit, toStep3 } = await mountContinue()
      await toStep3()
      await fillSite(wrapper)
      await submit()
      const body = (api.PUT.mock.calls[0] as [string, { body: { sites: unknown[] } }])[1].body
      expect(body.sites).toEqual([
        {
          id: 'my-shop',
          name: 'My Shop',
          hosts: ['shop.example.com'],
          tls: { mode: 'acme' },
          upstreams: { targets: ['10.0.1.10:8080'] },
          policy: { mode: 'detect' },
        },
      ])
      expect(wrapper.get('[aria-current="step"]').text()).toContain('Done')
      expect(wrapper.text()).toContain('Detect mode logs suspicious requests')
      expect(wrapper.get('a[href="/sites"]').text()).toContain('Go to sites')
    })

    it('validates required fields and maps server errors and conflicts to fields', async () => {
      existingConfig()
      const { wrapper, submit, toStep3 } = await mountContinue()
      await toStep3()
      await submit()
      expect(errorOf(wrapper, 'Site ID')).toContain('lowercase')
      expect(errorOf(wrapper, 'Public hostname')).toContain('at least one hostname')
      expect(errorOf(wrapper, 'Upstream address')).toContain('at least one upstream')
      expect(api.POST).not.toHaveBeenCalled()

      await fillSite(wrapper)
      api.POST.mockResolvedValueOnce(
        problem(422, {
          errors: [{ path: '/sites/1/upstreams/targets/0', code: 'x', message: 'bad address' }],
        }),
      )
      await submit()
      expect(errorOf(wrapper, 'Upstream address')).toBe('Line 1: bad address')

      api.POST.mockResolvedValueOnce(problem(409))
      await submit()
      expect(errorOf(wrapper, 'Site ID')).toContain('already exists')
      expect(wrapper.get('[aria-current="step"]').text()).toContain('First site')
    })
  })

  it('is keyboard operable: every step is a form that submits on Enter', async () => {
    const { wrapper, toStep3 } = await mountContinue()
    expect(wrapper.find('form button[type="submit"]').exists()).toBe(true)
    await toStep3()
    expect(wrapper.find('form button[type="submit"]').exists()).toBe(true)
  })
})
