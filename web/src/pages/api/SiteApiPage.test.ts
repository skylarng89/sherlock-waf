import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'

import SiteApiPage from './SiteApiPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>
beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

const site = (policyApi?: object) => ({
  id: 'bank',
  name: 'Bank',
  hosts: ['api.bank.test'],
  upstreams: { targets: ['10.0.0.1:80'] },
  policy: { mode: 'block', ...(policyApi ? { api: policyApi } : {}) },
})

const doc = {
  id: 'pay',
  name: 'Payments',
  version: '3.1',
  sha256: 'x',
  endpoint_count: 2,
  updated_at: '2026-01-01T00:00:00Z',
}

async function mount(me = adminMe, policyApi?: object) {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/sites') return ok({ items: [site(policyApi)] }, { etag: '"v3"' })
    if (path === '/defaults') return ok({})
    if (path === '/api-docs') return ok({ items: [doc] })
    if (path === '/ca-bundles') return ok({ items: [] })
    if (path === '/api-docs/{id}/endpoints') {
      return ok({
        items: [
          { method: 'GET', path: '/accounts/{id}', schema_violations: 4 },
          { method: 'POST', path: '/payments', schema_violations: 0 },
        ],
        undocumented: [{ method: 'GET', path: '/admin', count: 9 }],
      })
    }
    return problem(404)
  })
  return renderWithApp(SiteApiPage, { me, route: '/sites/bank/api' })
}
const submit = async (w: Awaited<ReturnType<typeof mount>>['wrapper']) => {
  await w.get('form').trigger('submit')
  await flushPromises()
}

describe('site API tab', () => {
  it('lists endpoints with violation counts and undocumented requests', async () => {
    const { wrapper } = await mount(adminMe, { enabled: true, openapi_doc_id: 'pay' })
    const rows = wrapper.findAll('[data-testid="api-endpoints"] tbody tr')
    expect(rows).toHaveLength(2)
    expect(rows[0]?.text()).toContain('/accounts/{id}')
    expect(rows[0]?.text()).toContain('4')
    expect(wrapper.get('[data-testid="api-undocumented"]').text()).toContain('GET /admin — 9')
    expect(api.GET).toHaveBeenCalledWith(
      '/api-docs/{id}/endpoints',
      expect.objectContaining({ params: { path: { id: 'pay' }, query: { site: 'bank' } } }),
    )
  })

  it('saves a merge patch with the new actions and a JWT rule', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v4"' }))
    const { wrapper } = await mount(adminMe, { enabled: true, openapi_doc_id: 'pay' })
    const selects = wrapper.findAll('select')
    const unknown = selects.find((s) => s.attributes('id')?.length && s.text().includes('Block'))
    await unknown?.setValue('block')
    await wrapper
      .findAll('button')
      .find((b) => b.text().includes('Add rule'))
      ?.trigger('click')
    const rule = wrapper.get('[data-testid="jwt-rule-0"]')
    const inputs = rule.findAll('input[type="text"]')
    await inputs[2]?.setValue('https://auth.bank.test/jwks.json')
    await inputs[3]?.setValue('https://auth.bank.test/')
    await inputs[4]?.setValue('open-banking')
    await submit(wrapper)
    const [path, init] = api.PATCH.mock.calls[0] as [
      string,
      { params: unknown; body: { policy: { api: Record<string, unknown> & { jwt: unknown[] } } } },
    ]
    expect(path).toBe('/sites/{site}')
    expect(init.params).toEqual({ path: { site: 'bank' }, header: { 'If-Match': '"v3"' } })
    const sent = init.body.policy.api
    expect(sent.unknown_path_action).toBe('block')
    expect(sent.jwt).toHaveLength(1)
    expect(sent.jwt[0]).toMatchObject({
      jwks_url: 'https://auth.bank.test/jwks.json',
      issuer: 'https://auth.bank.test/',
      audiences: ['open-banking'],
      match: { paths: ['/*'] },
      action: 'block',
    })
  })

  it('routes server-side field errors to the rule', async () => {
    api.PATCH.mockResolvedValue(
      problem(422, {
        errors: [
          {
            path: '/sites/0/policy/api/jwt/0/jwks_url',
            code: 'invalid',
            message: 'must be an https URL',
          },
        ],
      }),
    )
    const { wrapper } = await mount(adminMe, {
      enabled: true,
      jwt: [{ jwks_url: 'http://x', issuer: 'i' }],
    })
    await wrapper.get('[data-testid="jwt-rule-0"] input[type="text"]').setValue('/other/*')
    await submit(wrapper)
    expect(wrapper.text()).toContain('must be an https URL')
  })

  it('is read-only without config:write', async () => {
    const { wrapper } = await mount(viewerMe, { enabled: true })
    expect(wrapper.text()).toContain('You can view this policy but not change it.')
    expect(wrapper.findAll('button[type="submit"]')).toHaveLength(0)
    expect(wrapper.text()).not.toContain('Upload document')
  })
})
