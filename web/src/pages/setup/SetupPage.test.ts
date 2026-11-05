import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import type { mockClient } from '@/api/testing'
import { ok, problem } from '@/api/testing'
import { control, errorOf } from '@/pages/sites/testing'
import { useSessionStore } from '@/stores/session'
import { renderWithApp } from '@/test-utils'
import SetupPage from './SetupPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

async function mountSetup() {
  const view = await renderWithApp(SetupPage, { route: '/setup' })
  const fill = async (overrides: Partial<Record<string, string>> = {}) => {
    const v = {
      token: 'tok-123',
      username: 'ada',
      password: 'correct horse battery',
      confirm: 'correct horse battery',
      ...overrides,
    }
    await control(view.wrapper, 'Setup token').setValue(v.token)
    await control(view.wrapper, 'Username').setValue(v.username)
    await control(view.wrapper, 'Password').setValue(v.password)
    await control(view.wrapper, 'Confirm password').setValue(v.confirm)
  }
  const submit = async () => {
    await view.wrapper.get('form').trigger('submit')
    await flushPromises()
  }
  return { ...view, fill, submit, session: useSessionStore() }
}

beforeEach(() => Object.values(api).forEach((fn) => fn.mockReset()))

describe('SetupPage (step 1)', () => {
  it('explains where the setup token lives and announces the step', async () => {
    const { wrapper } = await mountSetup()
    expect(wrapper.text()).toContain('setup-token')
    expect(wrapper.text()).toContain('data directory')
    expect(wrapper.get('[aria-current="step"]').text()).toContain('Administrator')
    expect(wrapper.get('nav [role="status"]').text()).toBe('Step 1 of 4: Administrator')
    expect(wrapper.findAll('h1')).toHaveLength(1)
  })

  it('validates locally before calling the server', async () => {
    const { wrapper, fill, submit } = await mountSetup()
    await fill({ token: '', username: 'a b', password: 'short', confirm: 'short' })
    await submit()
    expect(api.POST).not.toHaveBeenCalled()
    expect(errorOf(wrapper, 'Setup token')).toContain('Enter the setup token')
    expect(errorOf(wrapper, 'Username')).toContain('3 to 64')
    expect(errorOf(wrapper, 'Password')).toContain('12 characters')
    await fill({ confirm: 'different different' })
    await submit()
    expect(errorOf(wrapper, 'Confirm password')).toContain('do not match')
  })

  it('creates the admin, marks setup complete, signs in and continues to MFA enrolment', async () => {
    api.POST.mockImplementation((path: string) =>
      Promise.resolve(
        path === '/setup/admin'
          ? ok({ id: 'u1' }, { status: 201 })
          : ok({ status: 'mfa_enrol_required' }),
      ),
    )
    const { fill, submit, session, router } = await mountSetup()
    session.setupRequired = true
    await fill()
    await submit()
    expect(api.POST).toHaveBeenCalledWith('/setup/admin', {
      body: { setup_token: 'tok-123', username: 'ada', password: 'correct horse battery' },
    })
    expect(api.POST).toHaveBeenCalledWith('/auth/login', {
      body: { username: 'ada', password: 'correct horse battery' },
    })
    expect(session.setupRequired).toBe(false)
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('login-enrol'))
    expect(router.currentRoute.value.query.redirect).toBe('/welcome')
  })

  it('shows a wrong token (403) on the token field', async () => {
    api.POST.mockResolvedValue(problem(403))
    const { wrapper, fill, submit, session } = await mountSetup()
    session.setupRequired = true
    await fill()
    await submit()
    expect(errorOf(wrapper, 'Setup token')).toContain('not correct')
    expect(control(wrapper, 'Setup token').attributes('aria-invalid')).toBe('true')
    expect(session.setupRequired).toBe(true)
  })

  it('shows server validation errors next to their fields (400/422)', async () => {
    api.POST.mockResolvedValue(
      problem(400, { errors: [{ path: '/password', code: 'weak', message: 'too common' }] }),
    )
    const { wrapper, fill, submit } = await mountSetup()
    await fill()
    await submit()
    expect(errorOf(wrapper, 'Password')).toBe('too common')
  })

  it('announces throttling (429) and disables the button', async () => {
    api.POST.mockResolvedValue(problem(429, {}, { 'Retry-After': '30' }))
    const { wrapper, fill, submit } = await mountSetup()
    await fill()
    await submit()
    expect(wrapper.get('[role="alert"]').text()).toContain('30 seconds')
    expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeDefined()
  })

  it('reports an already-completed setup (409) with a link to sign in', async () => {
    api.POST.mockResolvedValue(problem(409))
    const { wrapper, fill, submit, session } = await mountSetup()
    session.setupRequired = true
    await fill()
    await submit()
    expect(wrapper.get('[role="alert"]').text()).toContain('already complete')
    expect(session.setupRequired).toBe(false)
    expect(wrapper.find('form').exists()).toBe(false)
  })

  it('falls back to a manual sign-in link when the automatic sign-in fails', async () => {
    api.POST.mockImplementation((path: string) =>
      Promise.resolve(path === '/setup/admin' ? ok({}, { status: 201 }) : problem(500)),
    )
    const { wrapper, fill, submit } = await mountSetup()
    await fill()
    await submit()
    expect(wrapper.get('[role="alert"]').text()).toContain('signing in automatically failed')
    expect(wrapper.get('[role="alert"] a').attributes('href')).toBe('/login?redirect=/welcome')
  })
})
