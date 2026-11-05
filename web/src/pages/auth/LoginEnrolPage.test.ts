import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { client } from '@/api/client'
import { mockClient, ok, problem } from '@/api/testing'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import { freshApp, renderWithApp, adminMe } from '@/test-utils'
import LoginEnrolPage from './LoginEnrolPage.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})

const api = client as unknown as ReturnType<typeof mockClient>
const enrolment = {
  secret: 'JBSWY3DPEHPK3PXP',
  otpauth_uri: 'otpauth://totp/Sherlock:ada?secret=JBSWY3DPEHPK3PXP&issuer=Sherlock',
}

async function mountEnrol(route = '/login/enrol') {
  const router = freshApp()
  useSessionStore().status = 'partial'
  api.GET.mockResolvedValue(problem(403, { type: 'urn:sherlock:problem:forbidden' }))
  return renderWithApp(LoginEnrolPage, { router, route })
}

describe('LoginEnrolPage', () => {
  beforeEach(() => {
    Object.values(api).forEach((fn) => fn.mockReset())
    sessionStorage.clear()
    localStorage.clear()
  })

  it('shows the secret for manual entry and a client-side QR code built as SVG', async () => {
    api.POST.mockResolvedValueOnce(ok(enrolment))
    const { wrapper } = await mountEnrol()
    expect(api.POST).toHaveBeenCalledWith('/auth/mfa/enroll')
    expect(wrapper.get('[data-testid="secret"]').text()).toBe('JBSW Y3DP EHPK 3PXP')
    const svg = wrapper.get('svg[role="img"]')
    expect(svg.attributes('aria-label')).toContain('QR code')
    expect(svg.get('path').attributes('d')?.length).toBeGreaterThan(100)
    expect(wrapper.html()).not.toContain('<img')
  })

  it('does not keep the secret in web storage', async () => {
    api.POST.mockResolvedValueOnce(ok(enrolment))
    await mountEnrol()
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain('JBSWY3DPEHPK3PXP')
  })

  it('confirms with a code, completes sign-in and redirects', async () => {
    api.POST.mockResolvedValueOnce(ok(enrolment)).mockResolvedValueOnce(ok(adminMe))
    const { wrapper, router } = await mountEnrol('/login/enrol?redirect=/sites')
    const input = wrapper.get('input[name="code"]')
    expect(input.attributes('autocomplete')).toBe('one-time-code')
    await input.setValue('654321')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api.POST).toHaveBeenLastCalledWith('/auth/mfa/enroll/confirm', {
      body: { code: '654321' },
    })
    await vi.waitFor(() => expect(router.currentRoute.value.fullPath).toBe('/sites'))
    expect(useSessionStore().isAuthenticated).toBe(true)
  })

  it('shows a field error for a wrong confirmation code', async () => {
    api.POST.mockResolvedValueOnce(ok(enrolment)).mockResolvedValueOnce(problem(401))
    const { wrapper } = await mountEnrol()
    await wrapper.get('input[name="code"]').setValue('111111')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.get('input[name="code"]').attributes('aria-invalid')).toBe('true')
    expect(wrapper.text()).toContain('That code is not valid')
  })

  it('reports a failure to start enrolment instead of an empty page', async () => {
    api.POST.mockResolvedValueOnce(problem(500, { request_id: 'req-7' }))
    const { wrapper } = await mountEnrol()
    expect(wrapper.get('[role="alert"]').text()).toContain('Could not start two-step setup')
    expect(wrapper.find('svg').exists()).toBe(false)
    expect(useToastStore().items[0]?.requestId).toBe('req-7')
  })
})
