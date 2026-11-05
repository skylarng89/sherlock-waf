import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import EventDetailPage from '@/pages/events/EventDetailPage.vue'
import ExclusionWizard from './ExclusionWizard.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>
beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

const proposal = (critical: boolean) => ({
  exclusion: {
    id: 'fp-942100-abc',
    description: 'Exclude ARGS:q from 942100',
    match: { paths: ['/search'], methods: ['GET'] },
    remove_targets: [{ rule_ids: ['942100'], target: 'ARGS:q' }],
  },
  impact: {
    from: '2026-10-01T00:00:00Z',
    to: '2026-10-29T00:00:00Z',
    events_scanned: 120,
    matching_events: 7,
    no_longer_triggering: 5,
    no_longer_blocking: 3,
    by_rule: { '942100': 7 },
    sample_event_ids: [],
    truncated: false,
  },
  warnings: critical
    ? [{ code: 'whole_category', severity: 'critical', message: 'Disables SQL injection checks' }]
    : [{ code: 'broad_scope', severity: 'info', message: 'Matches many requests' }],
  requires_acknowledgement: critical,
})

function serve(critical: boolean) {
  api.POST.mockImplementation(async (path: string) =>
    path === '/sites/{site}/exclusions/propose' ? ok(proposal(critical)) : ok({}, { status: 201 }),
  )
  api.GET.mockResolvedValue(ok({ items: [] }, { etag: '"v7"' }))
}

async function mountWizard() {
  return renderWithApp(ExclusionWizard, {
    me: adminMe,
    props: {
      open: true,
      site: 'shop',
      eventId: 'e1',
      findings: [{ ruleId: '942100', message: 'SQLi' }],
    },
  })
}

describe('exclusion wizard', () => {
  it('proposes the narrowest scope with impact counts and creates it with If-Match', async () => {
    serve(false)
    const { wrapper } = await mountWizard()
    expect(api.POST).toHaveBeenCalledWith(
      '/sites/{site}/exclusions/propose',
      expect.objectContaining({
        body: expect.objectContaining({ event_id: 'e1', scope: 'target' }),
      }),
    )
    expect(wrapper.get('[data-testid="impact-matching"]').text()).toBe('7')
    expect(wrapper.get('[data-testid="impact-no-block"]').text()).toBe('3')
    expect(wrapper.get('[data-testid="wizard-proposal"]').text()).toContain('ARGS:q')
    // No critical warning: one click creates it.
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    const create = api.POST.mock.calls.find((c) => c[0] === '/sites/{site}/exclusions')
    expect(create?.[1]).toMatchObject({
      params: { path: { site: 'shop' }, header: { 'If-Match': '"v7"' } },
      body: { event_id: 'e1', exclusion: { id: 'fp-942100-abc' } },
    })
    expect(wrapper.get('[data-testid="wizard-created"]').text()).toContain('fp-942100-abc')
  })

  it('blocks creation until a critical warning is acknowledged', async () => {
    serve(true)
    const { wrapper } = await mountWizard()
    const submit = wrapper.get('button[type="submit"]')
    expect(submit.attributes('disabled')).toBeDefined()
    expect(wrapper.get('[data-testid="wizard-warnings"]').text()).toContain('SQL injection')
    await wrapper.get('input[type="checkbox"]').setValue(true)
    expect(submit.attributes('disabled')).toBeUndefined()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    const create = api.POST.mock.calls.find((c) => c[0] === '/sites/{site}/exclusions')
    expect(create?.[1]).toMatchObject({ body: { acknowledge_warnings: true } })
  })

  it('offers a reload when the configuration changed underneath', async () => {
    serve(false)
    const { wrapper } = await mountWizard()
    api.POST.mockImplementationOnce(async () => problem(412))
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('changed')
  })
})

describe('event detail entry point', () => {
  const event = {
    id: 'e1',
    ts: '2026-10-29T11:00:00Z',
    site_id: 'shop',
    action: 'block',
    request: { method: 'GET', path: '/search' },
    findings: [{ rule_id: '942100', module: 'waf', severity: 'critical', message: 'SQLi' }],
  }
  const get = async (path: string) => (path === '/events/{id}' ? ok(event) : ok({ items: [] }))

  it('shows the button to editors only', async () => {
    api.GET.mockImplementation(get)
    const admin = await renderWithApp(EventDetailPage, { me: adminMe, route: '/events/e1' })
    expect(admin.wrapper.find('[data-testid="create-exclusion"]').exists()).toBe(true)
    admin.wrapper.unmount()
    api.GET.mockImplementation(get)
    const viewer = await renderWithApp(EventDetailPage, { me: viewerMe, route: '/events/e1' })
    expect(viewer.wrapper.find('[data-testid="create-exclusion"]').exists()).toBe(false)
  })
})
