import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok } from '@/api/testing'
import { adminMe, renderWithApp } from '@/test-utils'
import CrsRulesPage from './CrsRulesPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>
beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

const rule = {
  id: 942100,
  message: '<b>SQL Injection</b> detected',
  category: 'attack-sqli',
  paranoia_level: 1,
  severity: 'CRITICAL',
  direction: 'request',
  phase: 2,
  tags: [],
  file: 'x.conf',
  status: { state: 'partly_excluded', reason: 'scoped_exclusion', excluded_by: ['fp-1'] },
}

describe('CRS rules page', () => {
  beforeEach(() => {
    api.GET.mockImplementation(async (path: string) =>
      path === '/sites'
        ? ok({ items: [{ id: 'blog' }] })
        : ok({ crs_version: '4.8.0', total: 1, categories: ['attack-sqli'], items: [rule] }),
    )
  })

  it('renders rules as text and passes filters, with per-site state', async () => {
    const { wrapper } = await renderWithApp(CrsRulesPage, { me: adminMe })
    expect(wrapper.get('[data-testid="crs-total"]').text()).toContain('4.8.0')
    expect(wrapper.get('[data-testid="crs-table"]').find('b').exists()).toBe(false)
    expect(wrapper.get('[data-testid="crs-table"]').text()).toContain('<b>SQL Injection</b>')
    await wrapper.get('#crs-q').setValue('sql')
    await wrapper.get('#crs-site').setValue('blog')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api.GET).toHaveBeenLastCalledWith(
      '/crs/rules',
      expect.objectContaining({
        params: { query: expect.objectContaining({ q: 'sql', site: 'blog', offset: 0 }) },
      }),
    )
    const state = wrapper.get('[data-testid="crs-state"]').text()
    expect(state).toContain('Partly excluded')
    expect(wrapper.get('[data-testid="crs-table"]').text()).toContain('fp-1')
  })
})
