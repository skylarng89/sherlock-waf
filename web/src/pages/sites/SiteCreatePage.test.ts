import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp } from '@/test-utils'
import SiteCreatePage from './SiteCreatePage.vue'
import { blog, control, errorOf, overrideToggle, serve } from './testing'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

const lookups = {
  '/defaults': () => ok({ mode: 'detect' }),
  '/certificates': () =>
    ok({
      items: [
        {
          id: 'cert1',
          name: 'Wildcard',
          hosts: ['*.example.com'],
          not_before: '',
          not_after: '',
          issuer: '',
          fingerprint_sha256: '',
          created_at: '',
        },
      ],
    }),
  '/block-pages': () => ok({ items: [{ id: 'friendly', updated_at: '', size_bytes: 1 }] }),
}

async function mountCreate(sitesResponse = () => ok({ items: [blog] }, { etag: '"v3"' })) {
  serve(api, { ...lookups, '/sites': sitesResponse })
  const view = await renderWithApp(SiteCreatePage, { me: adminMe, route: '/sites/new' })
  const fill = async () => {
    await control(view.wrapper, 'Site ID').setValue('shop')
    await control(view.wrapper, 'Hostnames').setValue('shop.example.com')
    await control(view.wrapper, 'Upstream targets').setValue('10.0.1.10:8080')
  }
  const submit = async () => {
    await view.wrapper.get('form').trigger('submit')
    await flushPromises()
  }
  return { ...view, fill, submit }
}

beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

describe('SiteCreatePage', () => {
  it('creates a site with POST /sites and the list ETag as If-Match, then opens it', async () => {
    api.POST.mockResolvedValue(ok({ id: 'v4' }, { status: 201, etag: '"v4"' }))
    const { fill, submit, router } = await mountCreate()
    await fill()
    await submit()
    expect(api.POST).toHaveBeenCalledWith(
      '/sites',
      expect.objectContaining({
        params: { header: { 'If-Match': '"v3"' } },
        body: expect.objectContaining({
          id: 'shop',
          hosts: ['shop.example.com'],
          upstreams: expect.objectContaining({ targets: ['10.0.1.10:8080'] }),
          policy: { mode: 'detect' },
        }),
      }),
    )
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('site-detail'))
    expect(router.currentRoute.value.params.site).toBe('shop')
  })

  it('validates the slug and required lists before calling the server', async () => {
    const { wrapper, submit } = await mountCreate()
    await control(wrapper, 'Site ID').setValue('Not A Slug')
    await submit()
    expect(api.POST).not.toHaveBeenCalled()
    expect(errorOf(wrapper, 'Site ID')).toContain('lowercase letters')
    expect(errorOf(wrapper, 'Hostnames')).toContain('at least one hostname')
    expect(errorOf(wrapper, 'Upstream targets')).toContain('at least one upstream')
    expect(control(wrapper, 'Site ID').attributes('aria-invalid')).toBe('true')
  })

  it('shows a duplicate id (409) on the id field', async () => {
    api.POST.mockResolvedValue(problem(409, { title: 'Conflict' }))
    const { wrapper, fill, submit } = await mountCreate()
    await fill()
    await submit()
    expect(errorOf(wrapper, 'Site ID')).toContain('already exists')
  })

  it('maps /sites/<index>/... pointers (the new site is appended) onto its fields', async () => {
    api.POST.mockResolvedValue(
      problem(422, {
        errors: [
          { path: '/sites/1/hosts/0', code: 'invalid_host', message: 'not a hostname' },
          { path: '/sites/1/upstreams/targets/0', code: 'invalid', message: 'bad address' },
          { path: '/sites/1/tls/mode', code: 'x', message: 'tls problem' },
          { path: '/sites/1/headers/oops', code: 'x', message: 'headers problem' },
          { path: '/sites/0/hosts/0', code: 'x', message: 'someone else' },
        ],
      }),
    )
    const { wrapper, fill, submit } = await mountCreate()
    await fill()
    await submit()
    expect(errorOf(wrapper, 'Hostnames')).toBe('Line 1: not a hostname')
    expect(errorOf(wrapper, 'Upstream targets')).toBe('Line 1: bad address')
    expect(errorOf(wrapper, 'TLS mode')).toBe('tls problem')
    const alerts = wrapper.findAll('[role="alert"]').map((a) => a.text())
    expect(alerts.join(' ')).toContain('headers problem')
    expect(alerts.join(' ')).toContain('someone else')
  })

  it('offers a reload on 412 and 428', async () => {
    api.POST.mockResolvedValueOnce(problem(412))
    const { wrapper, fill, submit } = await mountCreate()
    await fill()
    await submit()
    expect(wrapper.get('[role="alert"]').text()).toContain('changed by someone else')
    api.GET.mockClear()
    await wrapper.get('[role="alert"] button').trigger('click')
    await flushPromises()
    expect(api.GET).toHaveBeenCalledWith('/sites')
    api.POST.mockResolvedValueOnce(problem(428))
    await submit()
    expect(wrapper.get('[role="alert"]').text()).toContain('missing its version')
  })

  it('writes the first configuration with PUT /config and no If-Match on a fresh node', async () => {
    api.PUT.mockResolvedValue(ok({ id: 'v1' }, { etag: '"v1"' }))
    const { fill, submit } = await mountCreate(() => problem(404))
    await fill()
    await submit()
    expect(api.POST).not.toHaveBeenCalled()
    expect(api.PUT).toHaveBeenCalledWith(
      '/config',
      expect.objectContaining({
        params: { header: {} },
        body: expect.objectContaining({
          schema_version: 1,
          sites: [expect.objectContaining({ id: 'shop' })],
        }),
      }),
    )
  })

  it('populates the certificate picker from /certificates when TLS mode is file', async () => {
    const { wrapper } = await mountCreate()
    await control(wrapper, 'TLS mode').setValue('file')
    const options = control(wrapper, 'Certificate')
      .findAll('option')
      .map((o) => o.text())
    expect(options).toContain('Wildcard (*.example.com)')
    await overrideToggle(wrapper, 'Block page template').setValue(true)
    const pages = control(wrapper, 'Block page template')
      .findAll('option')
      .map((o) => o.text())
    expect(pages).toEqual(expect.arrayContaining(['default', 'friendly']))
  })

  it('asks for confirmation before creating a site in block mode', async () => {
    api.POST.mockResolvedValue(ok({}, { status: 201 }))
    const { wrapper, fill, submit } = await mountCreate()
    await fill()
    // The policy mode is an override of the global default; switch the override on.
    const toggle = wrapper.findAll('input[role="switch"]')[0]
    expect((toggle?.element as HTMLInputElement).checked).toBe(true)
    await control(wrapper, 'Mode').setValue('block')
    await submit()
    expect(api.POST).not.toHaveBeenCalled()
    expect((wrapper.get('dialog').element as HTMLDialogElement).open).toBe(true)
  })
})
