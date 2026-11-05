import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { useToastStore } from '@/stores/toasts'
import { adminMe, plainRouter, renderWithApp, viewerMe } from '@/test-utils'
import HistoryDetailPage from './HistoryDetailPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

const detail = {
  id: 'V1',
  parent_id: '',
  created_at: '2026-10-01T10:00:00Z',
  author_type: 'user',
  author_id: 'ada',
  source: 'api',
  schema_version: 1,
  applied: true,
  diff: {
    global: true,
    sites: {
      added: ['shop'],
      removed: ['old'],
      changed: [{ site: 'blog', fields: ['policy.mode', 'hosts'] }],
    },
  },
  snapshot: {
    schema_version: 1,
    sites: [{ id: '<img src=x onerror=alert(1)>', hosts: ['a.test'], upstreams: {} }],
  },
}

function setup(headEtag = '"V2"') {
  api.GET.mockImplementation(async (path: string) =>
    path === '/config' ? ok({}, { etag: headEtag }) : ok(detail),
  )
}

async function mountPage(me = adminMe) {
  setActivePinia(createPinia())
  const router = plainRouter()
  return renderWithApp(HistoryDetailPage, { me, router, route: '/history/V1' })
}

async function openAndConfirm(wrapper: Awaited<ReturnType<typeof mountPage>>['wrapper']) {
  await wrapper
    .findAll('button')
    .find((b) => b.text() === 'Roll back to this version')
    ?.trigger('click')
  await flushPromises()
  await wrapper.get('dialog form').trigger('submit')
  await flushPromises()
}

beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

describe('HistoryDetailPage', () => {
  it('renders metadata, the diff and the escaped snapshot', async () => {
    setup()
    const { wrapper } = await mountPage()
    expect(wrapper.text()).toContain('Global settings changed')
    expect(wrapper.text()).toContain('shop')
    expect(wrapper.text()).toContain('old')
    expect(wrapper.text()).toContain('policy.mode, hosts')
    const snap = wrapper.get('[data-testid="snapshot"]')
    expect(snap.text()).toContain('<img src=x onerror=alert(1)>')
    expect(wrapper.find('pre img').exists()).toBe(false)
  })

  it('hides rollback from viewers and disables it for the live version', async () => {
    setup()
    const viewer = await mountPage(viewerMe)
    expect(viewer.wrapper.text()).not.toContain('Roll back to this version')
    setup('"V1"')
    const admin = await mountPage()
    const btn = admin.wrapper
      .findAll('button')
      .find((b) => b.text() === 'Roll back to this version')
    expect(btn?.attributes('disabled')).toBeDefined()
    expect(admin.wrapper.text()).toContain('Current')
  })

  it('rolls back with If-Match from the head ETag', async () => {
    setup()
    api.POST.mockResolvedValueOnce(ok({ ...detail, id: 'V3' }, { etag: '"V3"' }))
    const { wrapper, router } = await mountPage()
    await openAndConfirm(wrapper)
    expect(api.POST).toHaveBeenCalledWith('/config/versions/{id}/rollback', {
      params: { path: { id: 'V1' }, header: { 'If-Match': '"V2"' } },
    })
    expect(useToastStore().items.at(-1)?.message).toContain('Rolled back to version V1')
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('history'))
  })

  it('offers a reload on 412', async () => {
    setup()
    api.POST.mockResolvedValueOnce(problem(412))
    const { wrapper } = await mountPage()
    await openAndConfirm(wrapper)
    expect(wrapper.get('[role="alert"]').text()).toContain('changed since this page was loaded')
    api.GET.mockClear()
    await wrapper
      .findAll('button')
      .find((b) => b.text() === 'Reload')
      ?.trigger('click')
    await flushPromises()
    expect(api.GET).toHaveBeenCalledWith('/config')
  })

  it('lists server field errors on 422', async () => {
    setup()
    api.POST.mockResolvedValueOnce(
      problem(422, {
        errors: [
          { path: '/sites/0/tls/certificate_id', code: 'missing', message: 'certificate gone' },
          {
            path: '/sites/1/policy/block_page/template_id',
            code: 'missing',
            message: 'block page gone',
          },
        ],
      }),
    )
    const { wrapper } = await mountPage()
    await openAndConfirm(wrapper)
    const items = wrapper.findAll('[role="alert"] li').map((l) => l.text())
    expect(items).toHaveLength(2)
    expect(items[0]).toContain('certificate gone')
    expect(items[1]).toContain('block page gone')
  })

  it('shows an error state when the version is missing', async () => {
    api.GET.mockResolvedValue(problem(404))
    const { wrapper } = await mountPage()
    expect(wrapper.get('[role="alert"]').text()).toContain('could not be loaded')
  })
})
