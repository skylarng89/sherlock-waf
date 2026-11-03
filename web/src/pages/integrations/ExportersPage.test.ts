import { flushPromises } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { buttonNamed, control, dialogWithTitle, serve } from '@/pages/sites/testing'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import ExportersPage from './ExportersPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

const NOW = new Date('2026-10-29T12:00:00Z')
const MASK = '********'
const stamp = { created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z' }

const siem = {
  id: 'siem',
  name: 'Corp SIEM',
  type: 'webhook',
  stream: 'both',
  enabled: true,
  settings: { url: MASK, hmac_secret: MASK, headers: { 'X-Api': MASK } },
  status: {
    running: true,
    sent: 1200,
    send_failures: 3,
    dropped: 2,
    pending: 10,
    spool_bytes: 2048,
    last_success: '2026-10-29T11:59:00Z',
    last_error: 'connection refused',
    last_error_at: '2026-10-29T11:58:00Z',
  },
  ...stamp,
}
const ext = {
  id: 'hec',
  name: 'Splunk HEC',
  type: 'splunk-hec',
  stream: 'events',
  enabled: false,
  settings: { token: MASK, index: 'main' },
  status: { running: false, sent: 0, send_failures: 0, dropped: 0, pending: 0, spool_bytes: 0 },
  ...stamp,
}

let list: unknown[] = [siem, ext]
let types = ['syslog', 'webhook', 'otlp', 'splunk-hec']

async function mountPage(me = adminMe) {
  serve(api, {
    '/exporters': () => ok({ items: list }),
    '/integrations/types': () => ok({ exporters: types, channels: [], alert_kinds: [] }),
  })
  return renderWithApp(ExportersPage, { me, route: '/integrations/exporters' })
}

const submit = async (wrapper: Awaited<ReturnType<typeof mountPage>>['wrapper'], title: string) => {
  await dialogWithTitle(wrapper, title).get('form').trigger('submit')
  await flushPromises()
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] })
  vi.setSystemTime(NOW)
  list = [siem, ext]
  types = ['syslog', 'webhook', 'otlp', 'splunk-hec']
  Object.values(api).forEach((fn) => fn.mockReset())
  api.PUT.mockResolvedValue(ok({}))
})
afterEach(() => vi.useRealTimers())

describe('ExportersPage', () => {
  it('lists exporters with live delivery stats and relative times', async () => {
    const { wrapper } = await mountPage()
    const row = wrapper.get('[data-testid="exporter-siem"]')
    expect(row.text()).toContain('Corp SIEM')
    expect(row.text()).toContain('Events and audit log')
    expect(row.text()).toContain('Running')
    expect(row.text()).toContain('1200')
    expect(row.text()).toContain('2.0 KiB')
    expect(row.text()).toContain('1 minute ago')
    expect(row.text()).toContain('connection refused')
    expect(row.get('dd.font-medium').text()).toBe('2')
    expect(wrapper.get('[data-testid="exporter-hec"]').text()).toContain('Not running')
  })

  it('is read-only for viewers', async () => {
    const { wrapper } = await mountPage(viewerMe)
    expect(wrapper.text()).toContain('read-only access')
    expect(wrapper.find('[data-testid="exporter-add"]').exists()).toBe(false)
    expect(wrapper.find('dialog').exists()).toBe(false)
    expect(wrapper.find('[data-testid="exporter-siem"] input[type="checkbox"]').exists()).toBe(
      false,
    )
    expect(wrapper.find('[data-testid="exporter-siem"] button').exists()).toBe(false)
  })

  it('shows an empty state and a retryable load error', async () => {
    list = []
    const { wrapper } = await mountPage()
    expect(wrapper.text()).toContain('No exporters')
    serve(api, { '/exporters': () => problem(500), '/integrations/types': () => problem(500) })
    const failed = await renderWithApp(ExportersPage, {
      me: adminMe,
      route: '/integrations/exporters',
    })
    expect(failed.wrapper.get('[role="alert"]').text()).toContain('could not be loaded')
  })

  it('creates a syslog exporter with an id derived from the name', async () => {
    const { wrapper } = await mountPage()
    await buttonNamed(wrapper, 'Add exporter').trigger('click')
    await control(wrapper, 'Name').setValue('Corp Splunk')
    expect((control(wrapper, 'Identifier').element as HTMLInputElement).value).toBe('corp-splunk')
    await control(wrapper, 'Address').setValue('siem.example.com:6514')
    await control(wrapper, 'Transport').setValue('tls')
    await submit(wrapper, 'Add exporter')

    expect(api.PUT).toHaveBeenCalledWith('/exporters/{id}', {
      params: { path: { id: 'corp-splunk' } },
      body: {
        name: 'Corp Splunk',
        type: 'syslog',
        stream: 'events',
        enabled: true,
        settings: {
          network: 'tls',
          address: 'siem.example.com:6514',
          format: 'cef',
          facility: 16,
          app_name: 'sherlock',
          framing: 'octet',
        },
      },
    })
  })

  it('validates name and id before calling the API', async () => {
    const { wrapper } = await mountPage()
    await buttonNamed(wrapper, 'Add exporter').trigger('click')
    await control(wrapper, 'Identifier').setValue('Bad ID')
    await submit(wrapper, 'Add exporter')
    expect(api.PUT).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('Enter a name.')
    expect(wrapper.text()).toContain('lowercase letters, digits or hyphens')
  })

  it('keeps stored secrets when editing: masked values go back untouched', async () => {
    const { wrapper } = await mountPage()
    await buttonNamed(wrapper, 'Edit').trigger('click')
    const secret = control(wrapper, 'Signing secret')
    expect(secret.attributes('type')).toBe('password')
    expect(secret.attributes('placeholder')).toBe('unchanged')
    expect((secret.element as HTMLInputElement).value).toBe('')
    await submit(wrapper, 'Edit exporter')
    const body = api.PUT.mock.calls[0]?.[1].body
    expect(body.settings).toEqual({ url: MASK, hmac_secret: MASK, headers: { 'X-Api': MASK } })
    expect(api.PUT.mock.calls[0]?.[1].params.path.id).toBe('siem')
  })

  it('sends a retyped secret instead of the mask', async () => {
    const { wrapper } = await mountPage()
    await buttonNamed(wrapper, 'Edit').trigger('click')
    await control(wrapper, 'Signing secret').setValue('s'.repeat(40))
    await submit(wrapper, 'Edit exporter')
    expect(api.PUT.mock.calls[0]?.[1].body.settings.hmac_secret).toBe('s'.repeat(40))
    expect(api.PUT.mock.calls[0]?.[1].body.settings.url).toBe(MASK)
  })

  it('shows the 422 problem detail inline and keeps the dialog open', async () => {
    api.PUT.mockResolvedValue(problem(422, { detail: 'hmac_secret must be at least 32 bytes' }))
    const { wrapper } = await mountPage()
    await buttonNamed(wrapper, 'Edit').trigger('click')
    await submit(wrapper, 'Edit exporter')
    expect(wrapper.get('[data-testid="form-error"]').text()).toContain('at least 32 bytes')
    expect((dialogWithTitle(wrapper, 'Edit exporter').element as HTMLDialogElement).open).toBe(true)
  })

  it('tests a saved exporter from the dialog, passing its id so masked values are filled in', async () => {
    api.POST.mockResolvedValue(ok({ ok: false, error: 'connection refused' }))
    const { wrapper } = await mountPage()
    await buttonNamed(wrapper, 'Edit').trigger('click')
    await wrapper.get('[data-testid="dialog-test"]').trigger('click')
    await flushPromises()
    expect(api.POST).toHaveBeenCalledWith('/exporters/test', {
      body: {
        id: 'siem',
        type: 'webhook',
        stream: 'both',
        settings: { url: MASK, hmac_secret: MASK, headers: { 'X-Api': MASK } },
      },
    })
    const outcome = dialogWithTitle(wrapper, 'Edit exporter').get('[data-testid="test-outcome"]')
    expect(outcome.attributes('aria-live')).toBe('polite')
    expect(outcome.text()).toContain('The check failed: connection refused')
  })

  it('tests from a table row and reports success', async () => {
    api.POST.mockResolvedValue(ok({ ok: true }))
    const { wrapper } = await mountPage()
    await wrapper
      .get('[data-testid="exporter-siem"] button[aria-label="Test Corp SIEM"]')
      .trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="row-test"]').text()).toContain('Corp SIEM')
    expect(wrapper.get('[data-testid="row-test"]').text()).toContain('The check succeeded.')
  })

  it('turns a failed test request into a failed result, not a crash', async () => {
    api.POST.mockResolvedValue(problem(422, { detail: 'unknown exporter type "x"' }))
    const { wrapper } = await mountPage()
    await wrapper
      .get('[data-testid="exporter-siem"] button[aria-label="Test Corp SIEM"]')
      .trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="row-test"]').text()).toContain('unknown exporter type')
  })

  it('edits extension types as JSON', async () => {
    const { wrapper } = await mountPage()
    await wrapper.get('button[aria-label="Edit Splunk HEC"]').trigger('click')
    const json = control(wrapper, 'Settings (JSON)')
    expect(JSON.parse((json.element as HTMLTextAreaElement).value)).toEqual({
      token: MASK,
      index: 'main',
    })
    await json.setValue('{ nope')
    await submit(wrapper, 'Edit exporter')
    expect(api.PUT).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('Enter a valid JSON object.')
    await json.setValue('{"token":"********","index":"audit"}')
    await submit(wrapper, 'Edit exporter')
    expect(api.PUT.mock.calls[0]?.[1].body.settings).toEqual({ token: MASK, index: 'audit' })
  })

  it('toggles enabled with the stored (masked) settings and reloads', async () => {
    const { wrapper } = await mountPage()
    await wrapper.get('input[type="checkbox"]').setValue(false)
    await flushPromises()
    expect(api.PUT.mock.calls[0]?.[1].body).toMatchObject({
      enabled: false,
      settings: siem.settings,
    })
    expect(api.GET.mock.calls.filter((c) => c[0] === '/exporters')).toHaveLength(2)
  })

  it('deletes after confirmation', async () => {
    api.DELETE.mockResolvedValue(ok(undefined, { status: 204 }))
    const { wrapper } = await mountPage()
    await wrapper.get('button[aria-label="Delete Corp SIEM"]').trigger('click')
    await dialogWithTitle(wrapper, 'Delete Corp SIEM?').get('form').trigger('submit')
    await flushPromises()
    expect(api.DELETE).toHaveBeenCalledWith('/exporters/{id}', { params: { path: { id: 'siem' } } })
    expect(wrapper.text()).toContain('Exporter Corp SIEM deleted.')
  })

  it('refreshes delivery stats every 15 seconds and stops on unmount', async () => {
    const { wrapper } = await mountPage()
    const calls = () => api.GET.mock.calls.filter((c) => c[0] === '/exporters').length
    expect(calls()).toBe(1)
    await vi.advanceTimersByTimeAsync(15_000)
    expect(calls()).toBe(2)
    wrapper.unmount()
    await vi.advanceTimersByTimeAsync(60_000)
    expect(calls()).toBe(2)
  })
})
