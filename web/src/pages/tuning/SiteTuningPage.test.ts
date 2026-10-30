import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok } from '@/api/testing'
import { blog, buttonNamed, serve } from '@/pages/sites/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import SiteTuningPage from './SiteTuningPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>
beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

const exclusion = {
  id: 'fp-1',
  description: 'search box',
  match: { paths: ['/search'], methods: ['GET'] },
  remove_targets: [{ rule_ids: ['942100'], target: 'ARGS:q' }],
}

const impact = (over: Record<string, unknown> = {}) => ({
  site: 'blog',
  from: '2026-10-01T00:00:00Z',
  to: '2026-10-29T00:00:00Z',
  detection_paranoia_level: 2,
  blocking_paranoia_level: 1,
  target_paranoia_level: 2,
  inbound_threshold: 5,
  observable: true,
  events_scanned: 200,
  already_blocking: 10,
  additional_blocks: 12,
  by_rule: [{ rule_id: '942200', count: 9 }],
  by_path: [{ path: '/search', count: 12 }],
  sample_event_ids: [],
  truncated: false,
  ...over,
})

function setup(paranoia: ReturnType<typeof impact>) {
  serve(api, {
    '/sites': () =>
      ok({ items: [{ ...blog, policy: { waf: { paranoia_level: 1 } } }] }, { etag: '"c1"' }),
    '/defaults': () => ok({}),
    '/sites/{site}/exclusions': () => ok({ items: [exclusion] }, { etag: '"c1"' }),
    '/sites/{site}/paranoia-impact': () => ok(paranoia),
  })
}

describe('site tuning page', () => {
  it('lists exclusions and deletes one with If-Match', async () => {
    setup(impact())
    api.DELETE.mockResolvedValue(ok({}))
    const { wrapper } = await renderWithApp(SiteTuningPage, {
      me: adminMe,
      route: '/sites/blog/tuning',
    })
    expect(wrapper.get('[data-testid="exclusions-table"]').text()).toContain('ARGS:q')
    await buttonNamed(wrapper, 'Delete').trigger('click')
    await flushPromises()
    const dialog = wrapper
      .findAll('dialog')
      .find((d) => d.text().includes('Delete exclusion fp-1?'))
    await buttonNamed(dialog as NonNullable<typeof dialog>, 'Delete').trigger('submit')
    await dialog?.get('form').trigger('submit')
    await flushPromises()
    expect(api.DELETE).toHaveBeenCalledWith(
      '/sites/{site}/exclusions/{exclusion}',
      expect.objectContaining({
        params: { path: { site: 'blog', exclusion: 'fp-1' }, header: { 'If-Match': '"c1"' } },
      }),
    )
  })

  it('shows predicted additional blocks by rule and path before saving', async () => {
    setup(impact())
    const { wrapper } = await renderWithApp(SiteTuningPage, {
      me: adminMe,
      route: '/sites/blog/tuning',
    })
    await buttonNamed(wrapper, 'Predict impact').trigger('click')
    await flushPromises()
    expect(api.GET).toHaveBeenCalledWith(
      '/sites/{site}/paranoia-impact',
      expect.objectContaining({ params: { path: { site: 'blog' }, query: { target: 2 } } }),
    )
    expect(wrapper.get('[data-testid="pl-additional"]').text()).toContain('12')
    expect(wrapper.get('[data-testid="pl-by-rule"]').text()).toContain('942200')
    expect(wrapper.get('[data-testid="pl-by-path"]').text()).toContain('/search')
    expect(api.PATCH).not.toHaveBeenCalled()
  })

  it('explains an unobservable prediction and offers to raise detection first', async () => {
    setup(
      impact({
        observable: false,
        advice: 'Raise paranoia_level to 2 first.',
        target_paranoia_level: 2,
      }),
    )
    api.PATCH.mockResolvedValue(ok({}, { etag: '"c2"' }))
    const { wrapper } = await renderWithApp(SiteTuningPage, {
      me: adminMe,
      route: '/sites/blog/tuning',
    })
    await buttonNamed(wrapper, 'Predict impact').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="pl-not-observable"]').text()).toContain(
      'Raise paranoia_level',
    )
    expect(wrapper.find('[data-testid="pl-apply"]').exists()).toBe(false)
    await wrapper.get('[data-testid="pl-raise-detection"]').trigger('click')
    await flushPromises()
    expect(api.PATCH).toHaveBeenCalledWith(
      '/sites/{site}',
      expect.objectContaining({
        params: { path: { site: 'blog' }, header: { 'If-Match': '"c1"' } },
        body: { policy: { waf: { paranoia_level: 2 } } },
      }),
    )
  })

  it('is read-only for a viewer', async () => {
    setup(impact())
    const { wrapper } = await renderWithApp(SiteTuningPage, {
      me: viewerMe,
      route: '/sites/blog/tuning',
    })
    expect(wrapper.text()).toContain('ARGS:q')
    expect(wrapper.findAll('button').map((b) => b.text())).not.toContain('Delete')
    expect(wrapper.text()).toContain('but not change them')
    expect(wrapper.text()).not.toContain('Save outbound settings')
  })

  it('saves outbound inspection settings as a merge patch', async () => {
    setup(impact())
    api.PATCH.mockResolvedValue(ok({}, { etag: '"c2"' }))
    const { wrapper } = await renderWithApp(SiteTuningPage, {
      me: adminMe,
      route: '/sites/blog/tuning',
    })
    const toggle = wrapper.findAll('label').find((l) => l.text().includes('Inspect responses'))
    await toggle?.get('input').setValue(true)
    await wrapper.get('form[novalidate]').trigger('submit')
    await flushPromises()
    expect(api.PATCH).toHaveBeenCalledWith(
      '/sites/{site}',
      expect.objectContaining({
        body: {
          policy: {
            waf: {
              outbound_inspection: true,
              outbound_max_body_bytes: null,
              outbound_content_types: null,
            },
          },
        },
      }),
    )
  })
})
