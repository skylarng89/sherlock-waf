import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import { mockClient, ok, problem } from '@/api/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import BlockPagesPage from './BlockPagesPage.vue'
import CertificatesPage from './CertificatesPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

const cert = (id: string, notAfter: string) => ({
  id,
  name: `cert-${id}`,
  hosts: ['a.example.com'],
  not_before: '2020-01-01T00:00:00Z',
  not_after: notAfter,
  issuer: 'Test CA',
  fingerprint_sha256: 'ff',
  created_at: '2020-01-01T00:00:00Z',
})
const farFuture = '2099-01-01T00:00:00Z'
const longPast = '2001-01-01T00:00:00Z'

function mockGets(certs: unknown[], acme: unknown[] = [], pages: unknown[] = []) {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/certificates') return ok({ items: certs })
    if (path === '/certificates/acme-status') return ok({ items: acme })
    if (path === '/block-pages') return ok({ items: pages })
    return problem(404)
  })
}

beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

describe('CertificatesPage', () => {
  it('lists certificates with text expiry signals and ACME explanations', async () => {
    mockGets(
      [cert('1', farFuture), cert('2', longPast)],
      [
        { site: 's', host: 'h.example.com', state: 'failed', detail: 'dns' },
        { site: 's', host: 'i.example.com', state: 'issued', not_after: farFuture },
      ],
    )
    const { wrapper } = await renderWithApp(CertificatesPage, { me: adminMe })
    expect(wrapper.get('[data-testid="cert-1"]').text()).toContain('Valid,')
    expect(wrapper.get('[data-testid="cert-2"]').text()).toContain('Expired')
    expect(wrapper.text()).toContain('The certificate could not be issued')
    expect(wrapper.text()).toContain('renews automatically')
    expect(wrapper.get('h1').text()).toBe('Certificates')
  })

  it('shows an empty state', async () => {
    mockGets([])
    const { wrapper } = await renderWithApp(CertificatesPage, { me: adminMe })
    expect(wrapper.text()).toContain('No certificates uploaded')
  })

  it('shows a load error with retry', async () => {
    api.GET.mockResolvedValue(problem(500, { detail: 'boom' }))
    const { wrapper } = await renderWithApp(CertificatesPage, { me: adminMe })
    expect(wrapper.find('[role="alert"]').text()).toContain('boom')
  })

  it('hides write actions from a viewer', async () => {
    mockGets([cert('1', farFuture)])
    const { wrapper } = await renderWithApp(CertificatesPage, { me: viewerMe })
    expect(wrapper.find('textarea[name="private_key_pem"]').exists()).toBe(false)
    expect(wrapper.find('button[aria-label^="Delete"]').exists()).toBe(false)
  })

  it('uploads, clears the key, and reloads', async () => {
    mockGets([])
    api.POST.mockResolvedValueOnce(ok(cert('3', farFuture), { status: 201 }))
    const { wrapper } = await renderWithApp(CertificatesPage, { me: adminMe })
    await wrapper.get('input[name="name"]').setValue('mine')
    await wrapper.get('textarea[name="certificate_pem"]').setValue('CERT')
    const key = wrapper.get('textarea[name="private_key_pem"]')
    await key.setValue('SECRETKEY')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api.POST).toHaveBeenCalledWith('/certificates', {
      body: { name: 'mine', certificate_pem: 'CERT', private_key_pem: 'SECRETKEY' },
    })
    expect((key.element as HTMLTextAreaElement).value).toBe('')
    expect(wrapper.html()).not.toContain('SECRETKEY')
    expect(api.GET.mock.calls.filter((c) => c[0] === '/certificates').length).toBe(2)
  })

  it('puts server errors on the right field and still clears the key', async () => {
    mockGets([])
    api.POST.mockResolvedValueOnce(
      problem(400, {
        errors: [{ path: '/private_key_pem', code: 'mismatch', message: 'key does not match' }],
      }),
    )
    const { wrapper } = await renderWithApp(CertificatesPage, { me: adminMe })
    await wrapper.get('input[name="name"]').setValue('mine')
    await wrapper.get('textarea[name="private_key_pem"]').setValue('SECRETKEY')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    const key = wrapper.get('textarea[name="private_key_pem"]')
    expect(key.attributes('aria-invalid')).toBe('true')
    expect(wrapper.get(`#${key.attributes('id')}-error`).text()).toContain('does not match')
    expect((key.element as HTMLTextAreaElement).value).toBe('')
  })

  it('shows the 409 body when deleting a certificate in use', async () => {
    mockGets([cert('1', farFuture)])
    api.DELETE.mockResolvedValueOnce(problem(409, { detail: 'used by site shop' }))
    const { wrapper } = await renderWithApp(CertificatesPage, { me: adminMe })
    await wrapper.get('button[aria-label="Delete certificate cert-1"]').trigger('click')
    await flushPromises()
    const confirm = wrapper.findAll('dialog button').find((b) => b.text() === 'Delete certificate')
    await confirm?.trigger('click')
    await flushPromises()
    expect(wrapper.get('dialog [role="alert"]').text()).toContain('used by site shop')
  })
})

describe('BlockPagesPage', () => {
  const page = { id: 'maint', updated_at: '2026-01-01T00:00:00Z', size_bytes: 12 }

  it('lists templates and previews hostile content inside a sandboxed frame', async () => {
    mockGets([], [], [page])
    const { wrapper } = await renderWithApp(BlockPagesPage, { me: adminMe })
    expect(wrapper.text()).toContain('maint')
    await wrapper.get('textarea[name="html"]').setValue('<script>alert(1)</script>{{.Detail}}')
    const frame = wrapper.get('iframe')
    expect(frame.attributes('sandbox')).toBe('')
    expect(frame.attributes('srcdoc')).toContain("default-src 'none'")
    expect(wrapper.html()).not.toMatch(/allow-scripts|allow-same-origin/)
  })

  it('saves a template and shows a 422 template error inline', async () => {
    mockGets([], [], [])
    api.PUT.mockResolvedValueOnce(
      problem(422, { errors: [{ path: '/html', code: 'template', message: 'unexpected {{' }] }),
    )
    const { wrapper } = await renderWithApp(BlockPagesPage, { me: adminMe })
    await wrapper.get('input[name="id"]').setValue('maint')
    await wrapper.get('textarea[name="html"]').setValue('{{')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api.PUT).toHaveBeenCalledWith('/block-pages/{id}', {
      params: { path: { id: 'maint' } },
      body: { html: '{{' },
    })
    expect(wrapper.get('textarea[name="html"]').attributes('aria-invalid')).toBe('true')
    expect(wrapper.text()).toContain('Template error: unexpected {{')
  })

  it('shows 409 when deleting a template in use', async () => {
    mockGets([], [], [page])
    api.DELETE.mockResolvedValueOnce(problem(409, { detail: 'used by site shop' }))
    const { wrapper } = await renderWithApp(BlockPagesPage, { me: adminMe })
    await wrapper.get('button[aria-label="Delete template maint"]').trigger('click')
    await flushPromises()
    await wrapper
      .findAll('dialog button')
      .find((b) => b.text() === 'Delete template')
      ?.trigger('click')
    await flushPromises()
    expect(wrapper.get('dialog [role="alert"]').text()).toContain('used by site shop')
  })
})
