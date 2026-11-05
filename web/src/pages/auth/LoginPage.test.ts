import { flushPromises } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import { mockClient, ok, problem } from '@/api/testing'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import { adminMe, renderWithApp } from '@/test-utils'
import LoginPage from './LoginPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})

const api = client as unknown as ReturnType<typeof mockClient>

async function mountLogin(route = '/login') {
  const view = await renderWithApp(LoginPage, { route })
  const submit = async (username = 'ada', password = 'correct horse') => {
    await view.wrapper.get('input[name="username"]').setValue(username)
    await view.wrapper.get('input[name="password"]').setValue(password)
    await view.wrapper.get('form').trigger('submit')
    await flushPromises()
  }
  return { ...view, submit }
}

describe('LoginPage', () => {
  beforeEach(() => {
    Object.values(api).forEach((fn) => fn.mockReset())
    localStorage.clear()
    sessionStorage.clear()
  })
  afterEach(() => vi.useRealTimers())

  it('renders labelled fields with the right autocomplete hints', async () => {
    const { wrapper } = await mountLogin()
    const user = wrapper.get('input[name="username"]')
    const pass = wrapper.get('input[name="password"]')
    expect(wrapper.get(`label[for="${user.attributes('id')}"]`).text()).toContain('Username')
    expect(wrapper.get(`label[for="${pass.attributes('id')}"]`).text()).toContain('Password')
    expect(pass.attributes('type')).toBe('password')
    expect(pass.attributes('autocomplete')).toBe('current-password')
    expect(user.attributes('autocomplete')).toBe('username')
    expect(wrapper.get('h1').text()).toBe('Sign in')
  })

  it('signs in and returns to the intended route', async () => {
    api.POST.mockResolvedValueOnce(ok({ status: 'ok', user: adminMe }))
    const { router, submit } = await mountLogin('/login?redirect=/audit')
    await submit()
    expect(api.POST).toHaveBeenCalledWith('/auth/login', {
      body: { username: 'ada', password: 'correct horse' },
    })
    await vi.waitFor(() => expect(router.currentRoute.value.fullPath).toBe('/audit'))
    expect(useSessionStore().isAuthenticated).toBe(true)
  })

  it('continues to the MFA step and keeps the return path', async () => {
    api.POST.mockResolvedValueOnce(ok({ status: 'mfa_required' }))
    const { router, submit } = await mountLogin('/login?redirect=/sites')
    await submit()
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('login-mfa'))
    expect(router.currentRoute.value.query.redirect).toBe('/sites')
  })

  it('goes to enrolment when the account has no authenticator yet', async () => {
    api.POST.mockResolvedValueOnce(ok({ status: 'mfa_enrol_required' }))
    const { router, submit } = await mountLogin()
    await submit()
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('login-enrol'))
  })

  it('ignores an off-site redirect', async () => {
    api.POST.mockResolvedValueOnce(ok({ status: 'ok', user: adminMe }))
    const { router, submit } = await mountLogin('/login?redirect=//evil.example')
    await submit()
    await vi.waitFor(() => expect(router.currentRoute.value.fullPath).toBe('/'))
  })

  it('shows one generic message for bad credentials and does not toast', async () => {
    api.POST.mockResolvedValueOnce(problem(401, { detail: 'user does not exist' }))
    const { wrapper, submit } = await mountLogin()
    await submit('nobody', 'wrong')
    const alert = wrapper.get('[role="alert"]')
    expect(alert.text()).toBe('Incorrect username or password.')
    expect(alert.text()).not.toContain('exist')
    expect(useToastStore().items).toHaveLength(0)
    expect(useSessionStore().status).not.toBe('authenticated')
  })

  it('clears the password after a successful first step', async () => {
    api.POST.mockResolvedValueOnce(ok({ status: 'mfa_required' }))
    const { wrapper, submit } = await mountLogin()
    await submit()
    expect((wrapper.get('input[name="password"]').element as HTMLInputElement).value).toBe('')
  })

  it('shows a throttling message with a countdown and re-enables when it ends', async () => {
    api.POST.mockResolvedValueOnce(problem(429, { retry_after_seconds: 3 }))
    const { wrapper, submit } = await mountLogin()
    vi.useFakeTimers()
    await submit()
    expect(wrapper.get('[role="alert"]').text()).toContain('Try again in 3 seconds')
    expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeDefined()
    expect(wrapper.get('[data-testid="countdown"]').text()).toBe('(3)')

    await vi.advanceTimersByTimeAsync(1000)
    expect(wrapper.get('[data-testid="countdown"]').text()).toBe('(2)')

    // A throttled submit makes no request.
    await wrapper.get('form').trigger('submit')
    expect(api.POST).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(2000)
    expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeUndefined()
    expect(wrapper.get('[role="status"]').text()).toContain('try signing in again')
  })

  it('places server validation errors next to the right field', async () => {
    api.POST.mockResolvedValueOnce(
      problem(400, {
        errors: [{ path: '/username', code: 'required', message: 'Username is required' }],
      }),
    )
    const { wrapper, submit } = await mountLogin()
    await submit('', 'x')
    const user = wrapper.get('input[name="username"]')
    expect(user.attributes('aria-invalid')).toBe('true')
    expect(wrapper.text()).toContain('Username is required')
    expect(wrapper.get('input[name="password"]').attributes('aria-invalid')).toBeUndefined()
  })

  it('toasts unexpected failures such as a network error', async () => {
    api.POST.mockRejectedValueOnce(new TypeError('offline'))
    const { submit } = await mountLogin()
    await submit()
    expect(useToastStore().items[0]?.message).toMatch(/could not be reached/)
  })

  it('announces the session-expired notice', async () => {
    const { wrapper } = await mountLogin('/login?expired=1')
    expect(wrapper.get('[role="status"]').text()).toContain('Your session has expired')
  })

  it('never writes credentials to web storage', async () => {
    api.POST.mockResolvedValueOnce(ok({ status: 'mfa_required' }))
    const { submit } = await mountLogin()
    await submit()
    const dump = JSON.stringify({ ...localStorage, ...sessionStorage })
    expect(dump).not.toContain('correct horse')
    expect(sessionStorage.length).toBe(0)
  })
})
