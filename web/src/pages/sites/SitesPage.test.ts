import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import SitesPage from './SitesPage.vue'
import { blog, serve, shop } from './testing'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

describe('SitesPage', () => {
  it('lists sites with mode badge, TLS, upstream count and a placeholder for blocks', async () => {
    serve(api, {
      '/sites': () => ok({ items: [blog, shop] }, { etag: '"v1"' }),
      '/defaults': () => ok({ mode: 'off' }),
    })
    const { wrapper } = await renderWithApp(SitesPage, { me: adminMe })
    const rows = wrapper.findAll('tbody tr')
    expect(rows).toHaveLength(2)
    // blog has no policy.mode, so the global default applies.
    expect(rows[0]?.text()).toContain('Off')
    expect(rows[0]?.text()).toContain('blog.example.com')
    expect(rows[1]?.text()).toContain('Shop')
    expect(rows[1]?.text()).toContain('Detect')
    expect(rows[1]?.text()).toContain('Automatic certificate')
    expect(rows[1]?.findAll('td')[3]?.text()).toBe('1')
    expect(rows[1]?.text()).toContain('—')
    expect(wrapper.get('caption').text()).not.toBe('')
    expect(wrapper.findAll('h1')).toHaveLength(1)
  })

  it('shows the empty state with an add button for admins only', async () => {
    serve(api, { '/sites': () => ok({ items: [] }), '/defaults': () => problem(404) })
    const admin = await renderWithApp(SitesPage, { me: adminMe })
    expect(admin.wrapper.text()).toContain('No sites yet')
    expect(admin.wrapper.findAll('button').some((b) => b.text().includes('Add site'))).toBe(true)
    admin.wrapper.unmount()
    const viewer = await renderWithApp(SitesPage, { me: viewerMe })
    expect(viewer.wrapper.text()).toContain('No sites yet')
    expect(viewer.wrapper.findAll('button').some((b) => b.text().includes('Add site'))).toBe(false)
  })

  it('announces loading and shows an alert with retry on failure', async () => {
    api.GET.mockResolvedValue(problem(500))
    const { wrapper } = await renderWithApp(SitesPage, { me: adminMe })
    expect(wrapper.get('[role="alert"]').text()).toContain('could not be loaded')
    serve(api, { '/sites': () => ok({ items: [blog] }), '/defaults': () => ok({}) })
    await wrapper.get('[role="alert"] button').trigger('click')
    await vi.waitFor(() => expect(wrapper.findAll('tbody tr')).toHaveLength(1))
  })
})
