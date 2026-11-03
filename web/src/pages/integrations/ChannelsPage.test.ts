import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { buttonNamed, control, dialogWithTitle, serve } from '@/pages/sites/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import ChannelsPage from './ChannelsPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

const MASK = '********'
const stamp = { created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z' }
const slack = {
  id: 'ops',
  name: 'Ops Slack',
  type: 'slack',
  enabled: true,
  settings: { url: MASK },
  ...stamp,
}

async function mountPage(me = adminMe) {
  serve(api, { '/notification-channels': () => ok({ items: [slack] }) })
  return renderWithApp(ChannelsPage, { me, route: '/integrations/channels' })
}

beforeEach(() => {
  Object.values(api).forEach((fn) => fn.mockReset())
  api.PUT.mockResolvedValue(ok({}))
})

describe('ChannelsPage', () => {
  it('lists channels and hides every action from viewers', async () => {
    const { wrapper } = await mountPage(viewerMe)
    expect(wrapper.get('[data-testid="channel-ops"]').text()).toContain('Slack')
    expect(wrapper.find('[data-testid="channel-add"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="channel-ops"] button').exists()).toBe(false)
  })

  it('creates an smtp channel with recipients as a list and no secret for an empty password', async () => {
    const { wrapper } = await mountPage()
    await buttonNamed(wrapper, 'Add channel').trigger('click')
    await control(wrapper, 'Name').setValue('Security mail')
    await control(wrapper, 'Type').setValue('smtp')
    await control(wrapper, 'SMTP host').setValue('mail.example.com')
    await control(wrapper, 'From address').setValue('sherlock@example.com')
    await control(wrapper, 'Recipients').setValue('a@example.com\nb@example.com\n')
    await dialogWithTitle(wrapper, 'Add notification channel').get('form').trigger('submit')
    await flushPromises()
    expect(api.PUT).toHaveBeenCalledWith('/notification-channels/{id}', {
      params: { path: { id: 'security-mail' } },
      body: {
        name: 'Security mail',
        type: 'smtp',
        enabled: true,
        settings: {
          host: 'mail.example.com',
          security: 'starttls',
          from: 'sherlock@example.com',
          to: ['a@example.com', 'b@example.com'],
        },
      },
    })
  })

  it('keeps a stored webhook URL when editing', async () => {
    const { wrapper } = await mountPage()
    await buttonNamed(wrapper, 'Edit').trigger('click')
    const url = control(wrapper, 'URL')
    expect(url.attributes('type')).toBe('password')
    expect(url.attributes('placeholder')).toBe('unchanged')
    await dialogWithTitle(wrapper, 'Edit notification channel').get('form').trigger('submit')
    await flushPromises()
    expect(api.PUT.mock.calls[0]?.[1].body.settings).toEqual({ url: MASK })
  })

  it('tests the channel with its id and reports the sanitized failure', async () => {
    api.POST.mockResolvedValue(ok({ ok: false, error: 'dial refused: link-local address' }))
    const { wrapper } = await mountPage()
    await wrapper.get('button[aria-label="Test Ops Slack"]').trigger('click')
    await flushPromises()
    expect(api.POST).toHaveBeenCalledWith('/notification-channels/test', {
      body: { id: 'ops', type: 'slack', settings: { url: MASK } },
    })
    expect(wrapper.get('[data-testid="row-test"]').text()).toContain('link-local')
  })

  it("shows the server's 409 when alert rules still use the channel", async () => {
    api.DELETE.mockResolvedValue(
      problem(409, { detail: 'the channel is used by alert rules Drops' }),
    )
    const { wrapper } = await mountPage()
    await wrapper.get('button[aria-label="Delete Ops Slack"]').trigger('click')
    await dialogWithTitle(wrapper, 'Delete Ops Slack?').get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.get('[data-testid="page-error"]').text()).toContain('used by alert rules Drops')
    expect(wrapper.find('[data-testid="channel-ops"]').exists()).toBe(true)
  })
})
