import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import { mockClient, ok, problem } from '@/api/testing'
import { adminMe, renderWithApp } from '@/test-utils'
import AccountPage from './AccountPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

const session = (id: string, current: boolean) => ({
  id,
  current,
  created_at: '2026-01-01T10:00:00Z',
  last_seen_at: '2026-01-01T10:30:00Z',
  expires_at: '2026-01-01T22:00:00Z',
})

const NEW_PASSWORD = 'a fresh passphrase here'

beforeEach(() => {
  Object.values(api).forEach((fn) => fn.mockReset())
  api.GET.mockResolvedValue(ok({ items: [session('s-current', true), session('s-other', false)] }))
})

async function fillPasswords(
  wrapper: Awaited<ReturnType<typeof renderWithApp>>['wrapper'],
  current: string,
  next: string,
  confirm = next,
) {
  await wrapper.get('input[name="current_password"]').setValue(current)
  await wrapper.get('input[name="new_password"]').setValue(next)
  await wrapper.get('input[name="confirm"]').setValue(confirm)
}

describe('AccountPage', () => {
  it('lists sessions, marks the current one and offers sign-out only for the others', async () => {
    const { wrapper } = await renderWithApp(AccountPage, { me: adminMe })
    expect(wrapper.get('[data-testid="session-current"]').text()).toContain('This session')
    const other = wrapper.get('[data-testid="session-other"]')
    expect(other.findAll('button').map((b) => b.text())).toEqual(['Sign out'])
    expect(wrapper.get('[data-testid="session-current"]').findAll('button')).toHaveLength(0)
  })

  it('signs another session out only after confirmation', async () => {
    api.DELETE.mockResolvedValueOnce(ok(undefined, { status: 204 }))
    const { wrapper } = await renderWithApp(AccountPage, { me: adminMe })
    await wrapper.get('[data-testid="session-other"] button').trigger('click')
    expect(api.DELETE).not.toHaveBeenCalled()

    await wrapper
      .findAll('dialog button')
      .find((b) => b.text() === 'Sign out session')
      ?.trigger('click')
    await flushPromises()
    expect(api.DELETE).toHaveBeenCalledWith('/auth/sessions/{id}', {
      params: { path: { id: 's-other' } },
    })
    expect(api.GET).toHaveBeenCalledTimes(2)
  })

  it('changes the password, reloads sessions and clears the fields', async () => {
    api.POST.mockResolvedValueOnce(ok(undefined, { status: 204 }))
    const { wrapper } = await renderWithApp(AccountPage, { me: adminMe })
    await fillPasswords(wrapper, 'the old passphrase', NEW_PASSWORD)
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(api.POST).toHaveBeenCalledWith('/auth/password', {
      body: { current_password: 'the old passphrase', new_password: NEW_PASSWORD },
    })
    expect(wrapper.get('input[name="new_password"]').element).toHaveProperty('value', '')
    expect(api.GET).toHaveBeenCalledTimes(2)
  })

  it('refuses a mismatched or short new password without calling the API', async () => {
    const { wrapper } = await renderWithApp(AccountPage, { me: adminMe })
    await fillPasswords(wrapper, 'the old passphrase', NEW_PASSWORD, 'something else entirely')
    await wrapper.get('form').trigger('submit')
    expect(wrapper.text()).toContain('do not match')

    await fillPasswords(wrapper, 'the old passphrase', 'short')
    await wrapper.get('form').trigger('submit')
    expect(wrapper.text()).toContain('at least 12 characters')
    expect(api.POST).not.toHaveBeenCalled()
  })

  it('shows a wrong current password against its own field', async () => {
    api.POST.mockResolvedValueOnce(
      problem(422, {
        type: 'urn:sherlock:problem:unprocessable',
        errors: [
          {
            path: '/current_password',
            code: 'incorrect',
            message: 'The current password is incorrect.',
          },
        ],
      }),
    )
    const { wrapper } = await renderWithApp(AccountPage, { me: adminMe })
    await fillPasswords(wrapper, 'wrong guess', NEW_PASSWORD)
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    const field = wrapper.get('input[name="current_password"]')
    expect(field.attributes('aria-invalid')).toBe('true')
    expect(wrapper.text()).toContain('The current password is incorrect.')
    expect(wrapper.get('input[name="current_password"]').element).toHaveProperty(
      'value',
      'wrong guess',
    )
  })

  it('shows the throttle message from a 429', async () => {
    api.POST.mockResolvedValueOnce(
      problem(429, { detail: 'Try again later.' }, { 'Retry-After': '60' }),
    )
    const { wrapper } = await renderWithApp(AccountPage, { me: adminMe })
    await fillPasswords(wrapper, 'wrong guess', NEW_PASSWORD)
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Try again later.')
  })

  it('shows a load error for sessions with a retry', async () => {
    api.GET.mockResolvedValueOnce(problem(500, { detail: 'boom' }))
    const { wrapper } = await renderWithApp(AccountPage, { me: adminMe })
    expect(wrapper.get('[role="alert"]').text()).toContain('boom')
  })
})
