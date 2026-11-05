import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import { mockClient, ok, problem } from '@/api/testing'
import { adminMe, renderWithApp } from '@/test-utils'
import UsersPage from './UsersPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})
const api = client as unknown as ReturnType<typeof mockClient>

const user = (id: string, username: string, extra: Record<string, unknown> = {}) => ({
  id,
  username,
  role: 'viewer',
  mfa_enabled: true,
  disabled: false,
  locked: false,
  last_login_at: null,
  created_at: '2026-01-01T00:00:00Z',
  ...extra,
})

beforeEach(() => {
  Object.values(api).forEach((fn) => fn.mockReset())
  api.GET.mockResolvedValue(
    ok({
      items: [
        user('u1', 'ada', { role: 'admin' }),
        user('u3', 'bob', { disabled: true, locked: true, mfa_enabled: false }),
      ],
    }),
  )
})

async function clickDialog(
  wrapper: Awaited<ReturnType<typeof renderWithApp>>['wrapper'],
  text: string,
) {
  await wrapper
    .findAll('dialog button')
    .find((b) => b.text() === text)
    ?.trigger('click')
  await flushPromises()
}

describe('UsersPage', () => {
  it('lists users with textual state', async () => {
    const { wrapper } = await renderWithApp(UsersPage, { me: adminMe })
    const bob = wrapper.get('[data-testid="user-bob"]').text()
    expect(bob).toContain('Disabled')
    expect(bob).toContain('Locked')
    expect(bob).toContain('Not enrolled')
    expect(bob).toContain('Never')
    expect(wrapper.get('[data-testid="user-ada"]').text()).toContain('(you)')
  })

  it('shows an empty state and a load error', async () => {
    api.GET.mockResolvedValueOnce(ok({ items: [] }))
    const empty = await renderWithApp(UsersPage, { me: adminMe })
    expect(empty.wrapper.text()).toContain('No users')
    api.GET.mockResolvedValueOnce(problem(500, { detail: 'boom' }))
    const failed = await renderWithApp(UsersPage, { me: adminMe })
    expect(failed.wrapper.find('[role="alert"]').text()).toContain('boom')
  })

  it('creates a user and wipes the password', async () => {
    api.POST.mockResolvedValueOnce(ok(user('u9', 'eve'), { status: 201 }))
    const { wrapper } = await renderWithApp(UsersPage, { me: adminMe })
    await wrapper.get('input[name="username"]').setValue('eve')
    const pw = wrapper.get('input[name="password"]')
    await pw.setValue('a-long-enough-password')
    await wrapper.get('select[name="role"]').setValue('admin')
    await wrapper.get('input[name="username"]').trigger('input')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api.POST).toHaveBeenCalledWith('/users', {
      body: { username: 'eve', password: 'a-long-enough-password', role: 'admin' },
    })
    expect((pw.element as HTMLInputElement).value).toBe('')
  })

  it('enforces the 12 character policy client-side', async () => {
    const { wrapper } = await renderWithApp(UsersPage, { me: adminMe })
    await wrapper.get('input[name="username"]').setValue('eve')
    await wrapper.get('input[name="password"]').setValue('short')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api.POST).not.toHaveBeenCalled()
    expect(wrapper.get('input[name="password"]').attributes('aria-invalid')).toBe('true')
  })

  it('places server field errors on the field', async () => {
    api.POST.mockResolvedValueOnce(
      problem(400, { errors: [{ path: '/username', code: 'taken', message: 'Already taken' }] }),
    )
    const { wrapper } = await renderWithApp(UsersPage, { me: adminMe })
    await wrapper.get('input[name="username"]').setValue('ada')
    await wrapper.get('input[name="password"]').setValue('a-long-enough-password')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    const input = wrapper.get('input[name="username"]')
    expect(input.attributes('aria-invalid')).toBe('true')
    expect(wrapper.get(`#${input.attributes('id')}-error`).text()).toContain('Already taken')
  })

  it('resets a password via PATCH and never keeps it', async () => {
    api.PATCH.mockResolvedValueOnce(ok(user('u3', 'bob')))
    const { wrapper } = await renderWithApp(UsersPage, { me: adminMe })
    await wrapper.get('button[aria-label="Reset password for bob"]').trigger('click')
    await flushPromises()
    await wrapper.get('input[name="dialog-password"]').setValue('another-long-password')
    await clickDialog(wrapper, 'Reset password')
    expect(api.PATCH).toHaveBeenCalledWith('/users/{id}', {
      params: { path: { id: 'u3' } },
      body: { password: 'another-long-password' },
    })
    expect(wrapper.html()).not.toContain('another-long-password')
  })

  it('resets MFA', async () => {
    api.POST.mockResolvedValueOnce(ok(null, { status: 204 }))
    const { wrapper } = await renderWithApp(UsersPage, { me: adminMe })
    await wrapper.get('button[aria-label="Reset MFA for bob"]').trigger('click')
    await flushPromises()
    await clickDialog(wrapper, 'Reset MFA')
    expect(api.POST).toHaveBeenCalledWith('/users/{id}/reset-mfa', {
      params: { path: { id: 'u3' } },
    })
  })

  it('requires the typed username to delete and shows a 409 clearly', async () => {
    api.DELETE.mockResolvedValueOnce(problem(409, { detail: 'cannot delete the last admin' }))
    const { wrapper } = await renderWithApp(UsersPage, { me: adminMe })
    await wrapper.get('button[aria-label="Delete for ada"]').trigger('click')
    await flushPromises()
    const confirm = wrapper.findAll('dialog button').find((b) => b.text() === 'Delete user')
    expect(confirm?.attributes('disabled')).toBeDefined()
    await wrapper.get('dialog input[type="text"]').setValue('ada')
    await clickDialog(wrapper, 'Delete user')
    expect(wrapper.get('dialog [role="alert"]').text()).toContain('cannot delete the last admin')
  })

  it('changes a role', async () => {
    api.PATCH.mockResolvedValueOnce(ok(user('u3', 'bob', { role: 'admin' })))
    const { wrapper } = await renderWithApp(UsersPage, { me: adminMe })
    await wrapper.get('button[aria-label="Change role for bob"]').trigger('click')
    await flushPromises()
    await wrapper.get('select[name="dialog-role"]').setValue('admin')
    await clickDialog(wrapper, 'Change role')
    expect(api.PATCH).toHaveBeenCalledWith('/users/{id}', {
      params: { path: { id: 'u3' } },
      body: { role: 'admin' },
    })
  })
})
