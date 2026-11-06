import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { control } from '@/pages/sites/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import SiteDlpPage from './SiteDlpPage.vue'

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
  return renderWithApp(SiteDlpPage, { me, route: '/sites/bank/data-protection' })
}
type Wrapper = Awaited<ReturnType<typeof mount>>['wrapper']
const submit = async (w: Wrapper) => {
  await w.get('form').trigger('submit')
  await flushPromises()
}
const click = async (w: Wrapper, text: string) => {
  await w
    .findAll('button')
    .find((b) => b.text().includes(text))
    ?.trigger('click')
  await flushPromises()
}
const sent = () =>
  (api.PATCH.mock.calls[0] as [string, { body: { policy: { dlp: Record<string, unknown> } } }])[1]
    .body.policy.dlp

describe('site data protection tab', () => {
  it('states that matched values are never stored and shows inherited values', async () => {
    const { wrapper } = await mount(
      adminMe,
      { mode: 'block' },
      {
        dlp: { action: 'block', max_body_bytes: 2048, detect: ['pan', 'iban'] },
      },
    )
    expect(wrapper.get('[data-testid="dlp-privacy"]').text()).toContain('never stored')
    expect(wrapper.text()).toContain('Inherited: block')
    expect(wrapper.text()).toContain('Inherited: 2048')
    expect(wrapper.text()).toContain('Inherited: pan, iban')
    const pan = wrapper.get('[data-testid="detect-pan"]').element as HTMLInputElement
    const iban = wrapper.get('[data-testid="detect-iban"]').element as HTMLInputElement
    expect([pan.checked, iban.checked]).toEqual([true, true])
  })

  it('warns in detect mode that nothing is masked or blocked', async () => {
    const { wrapper } = await mount(adminMe, { mode: 'detect' })
    expect(wrapper.get('[data-testid="mode-notice"]').text()).toContain('nothing is masked')
  })

  it('saves detectors, a custom pattern and the action as a merge patch', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v4"' }))
    const { wrapper } = await mount()
    await wrapper.get('[data-testid="detect-iban"]').setValue(true)
    await click(wrapper, 'Add pattern')
    const cp = wrapper.get('[data-testid="dlp-pattern-0"]')
    await cp.get('input[type="text"]').setValue('nin')
    await cp.get('textarea').setValue('[A-Z]{2}[0-9]{6}')
    await wrapper.get('[data-testid="detect-custom-nin"]').setValue(true)
    await control(wrapper, 'Action on a match').setValue('block')
    await submit(wrapper)
    expect(sent()).toEqual({
      detect: ['pan', 'iban', 'custom:nin'],
      custom_patterns: [{ name: 'nin', pattern: '[A-Z]{2}[0-9]{6}' }],
      action: 'block',
    })
  })

  it('refuses unsupported or invalid patterns before calling the API', async () => {
    const { wrapper } = await mount()
    await click(wrapper, 'Add pattern')
    const cp = wrapper.get('[data-testid="dlp-pattern-0"]')
    await cp.get('input[type="text"]').setValue('Bad Name')
    await cp.get('textarea').setValue('a(?=b)')
    await control(wrapper, 'Largest response scanned').setValue('10')
    await submit(wrapper)
    expect(api.PATCH).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('Use lower-case letters')
    expect(wrapper.text()).toContain(
      'Look-ahead, look-behind and back-references are not supported.',
    )
    expect(wrapper.text()).toContain('whole number from 1024 to 16777216')
    expect(control(wrapper, 'Largest response scanned').attributes('aria-invalid')).toBe('true')
  })

  it('drops a custom detector when its pattern is removed', async () => {
    api.PATCH.mockResolvedValue(ok({}, { etag: '"v4"' }))
    const { wrapper } = await mount(adminMe, {
      mode: 'block',
      dlp: { detect: ['pan', 'custom:nin'], custom_patterns: [{ name: 'nin', pattern: 'x+' }] },
    })
    await wrapper
      .get('[data-testid="dlp-pattern-0"]')
      .findAll('button')
      .find((b) => b.attributes('aria-label')?.includes('Remove pattern'))
      ?.trigger('click')
    await wrapper.get('[data-testid="detect-iban"]').setValue(true)
    await submit(wrapper)
    expect(sent().detect).toEqual(['pan', 'iban'])
    expect(api.PATCH.mock.calls[0]?.[1]).toMatchObject({
      body: { policy: { dlp: { custom_patterns: null } } },
    })
  })

  it('puts a server refusal on the own field of the pattern', async () => {
    api.PATCH.mockResolvedValue(
      problem(422, {
        errors: [
          {
            path: '/sites/0/policy/dlp/custom_patterns/0/pattern',
            code: 'invalid',
            message: 'not a valid RE2 expression',
          },
        ],
      }),
    )
    const { wrapper } = await mount(adminMe, {
      mode: 'block',
      dlp: { custom_patterns: [{ name: 'nin', pattern: 'x+' }] },
    })
    await control(wrapper, 'Action on a match').setValue('log')
    await submit(wrapper)
    expect(wrapper.text()).toContain('not a valid RE2 expression')
    expect(wrapper.text()).not.toContain('Line 1')
    expect(control(wrapper, 'Regular expression').attributes('aria-describedby')).toContain(
      '-error',
    )
  })

  it('is read-only without config:write', async () => {
    const { wrapper } = await mount(viewerMe, { mode: 'block', dlp: { enabled: true } })
    expect(wrapper.text()).toContain('You can view this policy but not change it.')
    expect(wrapper.findAll('button[type="submit"]')).toHaveLength(0)
    expect(wrapper.text()).not.toContain('Add pattern')
    expect((wrapper.get('[data-testid="detect-pan"]').element as HTMLInputElement).disabled).toBe(
      true,
    )
  })
})
