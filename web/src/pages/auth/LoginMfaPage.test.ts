import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import { mockClient, ok, problem } from '@/api/testing'
import { useSessionStore } from '@/stores/session'
import { freshApp, renderWithApp, viewerMe } from '@/test-utils'
import LoginMfaPage from './LoginMfaPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})

const api = client as unknown as ReturnType<typeof mockClient>
const partial = () => problem(403, { type: 'urn:sherlock:problem:forbidden' })

async function mountMfa(route = '/login/mfa') {
  const router = freshApp()
  useSessionStore().status = 'partial'
  api.GET.mockResolvedValue(partial())
  const view = await renderWithApp(LoginMfaPage, { router, route })
  const submit = async (code: string) => {
    await view.wrapper.get('input[name="code"]').setValue(code)
    await view.wrapper.get('form').trigger('submit')
    await flushPromises()
  }
  return { ...view, submit }
}

describe('LoginMfaPage', () => {
  beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

  it('uses a numeric one-time-code input', async () => {
    const { wrapper } = await mountMfa()
    const input = wrapper.get('input[name="code"]')
    expect(input.attributes('autocomplete')).toBe('one-time-code')
    expect(input.attributes('inputmode')).toBe('numeric')
    expect(input.attributes('maxlength')).toBe('6')
    expect(wrapper.get(`label[for="${input.attributes('id')}"]`).text()).toContain(
      'Authentication code',
    )
    expect(input.attributes('autofocus')).toBeUndefined()
  })

  it('verifies the code and continues to the intended route', async () => {
    api.POST.mockResolvedValueOnce(ok(viewerMe))
    const { router, submit } = await mountMfa('/login/mfa?redirect=/sites')
    await submit('123456')
    expect(api.POST).toHaveBeenCalledWith('/auth/mfa', { body: { code: '123456' } })
    await vi.waitFor(() => expect(router.currentRoute.value.fullPath).toBe('/sites'))
  })

  it('rejects a malformed code locally without calling the API', async () => {
    const { wrapper, submit } = await mountMfa()
    await submit('12ab')
    expect(api.POST).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('That code is not valid')
  })

  it('shows an error next to the field for a wrong code and clears the input', async () => {
    api.POST.mockResolvedValueOnce(problem(401))
    const { wrapper, submit } = await mountMfa()
    await submit('000000')
    const input = wrapper.get('input[name="code"]')
    expect(input.attributes('aria-invalid')).toBe('true')
    expect(wrapper.text()).toContain('That code is not valid')
    expect((input.element as HTMLInputElement).value).toBe('')
  })

  it('returns to sign-in with the expiry notice when the partial session lapsed', async () => {
    api.POST.mockResolvedValueOnce(problem(401))
    const { router, submit } = await mountMfa()
    api.GET.mockResolvedValue(problem(401))
    await submit('000000')
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('login'))
    expect(router.currentRoute.value.query.expired).toBe('1')
  })
})
