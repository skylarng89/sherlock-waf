import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok } from '@/api/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import CoveredCvesTile from './CoveredCvesTile.vue'
import VirtualPatchesPage from './VirtualPatchesPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>
beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

const catalogue = {
  pack_version: '2026.10.1',
  window_days: 7,
  known_stacks: ['wordpress'],
  truncated: false,
  items: [
    {
      id: 'vp-wp-1',
      title: 'WordPress plugin RCE',
      cves: ['CVE-2026-0001'],
      vendor: 'acme',
      product: 'plugin',
      versions: '<1.2',
      severity: 'critical',
      cvss: 9.8,
      kev: true,
      stacks: ['wordpress'],
      generic: false,
      references: ['https://example.test/x'],
      false_positive_notes: 'none',
      verification: 'synthetic',
      added_in: '2026.10.1',
      rule_ids: [100001],
      hits: 4,
      sites: [
        { site: 'blog', state: 'active', hits: 4 },
        { site: 'shop', state: 'stack_not_declared', hits: 0 },
      ],
    },
  ],
  covered: [
    {
      cve: 'CVE-2021-44228',
      product: 'log4j',
      kev: true,
      severity: 'critical',
      crs_rules: ['944150'],
    },
  ],
  summary: {
    patches: 1,
    covered_cves: 1,
    cves_with_rule: 1,
    kev_cves: 2,
    sites_protected: 1,
    hits: 4,
  },
}

function serve() {
  api.GET.mockImplementation(async (path: string) =>
    path === '/sites'
      ? ok({ items: [{ id: 'blog' }, { id: 'shop' }] }, { etag: '"c1"' })
      : ok(catalogue),
  )
}

describe('virtual patches page', () => {
  it('shows CVE, KEV badge, per-site state and hits', async () => {
    serve()
    const { wrapper } = await renderWithApp(VirtualPatchesPage, { me: adminMe })
    const table = wrapper.get('[data-testid="vp-table"]').text()
    expect(table).toContain('CVE-2026-0001')
    expect(table).toContain('Known exploited')
    expect(table).toContain('Active')
    expect(table).toContain('Stack not declared')
    expect(wrapper.get('[data-testid="vp-hits"]').text()).toBe('4')
    expect(wrapper.get('[data-testid="covered-table"]').text()).toContain('CVE-2021-44228')
  })

  it('switches a patch off for one site with If-Match', async () => {
    serve()
    api.PUT.mockResolvedValue(ok({}))
    const { wrapper } = await renderWithApp(VirtualPatchesPage, { me: adminMe })
    await wrapper.get('input[aria-label="vp-wp-1 on blog"]').setValue(false)
    await flushPromises()
    expect(api.PUT).toHaveBeenCalledWith(
      '/sites/{site}/virtual-patches/{patch}',
      expect.objectContaining({
        params: {
          path: { site: 'blog', patch: 'vp-wp-1' },
          header: { 'If-Match': '"c1"' },
        },
        body: { enabled: false },
      }),
    )
  })

  it('hides the switches from a viewer', async () => {
    serve()
    const { wrapper } = await renderWithApp(VirtualPatchesPage, { me: viewerMe })
    expect(wrapper.findAll('input[type="checkbox"][role="switch"]')).toHaveLength(0)
  })

  it('shows the covered CVEs tile from the summary', async () => {
    serve()
    const { wrapper } = await renderWithApp(CoveredCvesTile, { me: adminMe })
    expect(wrapper.get('[data-testid="covered-total"]').text()).toContain('2 CVEs')
    expect(wrapper.text()).toContain('2 known exploited')
  })
})
