import { describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { client } from '@/api/client'
import { mockClient, ok } from '@/api/testing'
import { registerNavItem, resetExtensions } from '@/extensions'
import { useSessionStore } from '@/stores/session'
import { useThemeStore } from '@/stores/theme'
import { adminMe, renderWithApp, viewerMe } from '@/test-utils'
import AppShell from './AppShell.vue'

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>()
  const { mockClient } = await import('@/api/testing')
  return { ...actual, client: mockClient() }
})

const slot = { default: '<h1 data-page-title tabindex="-1">Page</h1>' }

describe('AppShell', () => {
  it('has the header, nav and main landmarks and a skip link', async () => {
    const { wrapper } = await renderWithApp(AppShell, { me: adminMe, slots: slot })
    expect(wrapper.find('header').exists()).toBe(true)
    expect(wrapper.get('nav').attributes('aria-label')).toBe('Main navigation')
    expect(wrapper.find('main#main').exists()).toBe(true)
    const skip = wrapper.get('a[href="#main"]')
    await skip.trigger('click')
    expect(document.activeElement?.getAttribute('data-page-title')).not.toBeNull()
  })

  it('shows every nav item to an admin and hides admin-only items from a viewer', async () => {
    const admin = await renderWithApp(AppShell, { me: adminMe, slots: slot })
    const adminLinks = admin.wrapper.findAll('nav a').map((a) => a.text())
    expect(adminLinks).toEqual([
      'Overview',
      'Sites',
      'Global defaults',
      'Access',
      'Bans',
      'Certificates',
      'Attack explorer',
      'CRS rules',
      'Analytics',
      'Would-block report',
      'Virtual patches',
      'Config history',
      'Audit log',
      'Users',
      'API tokens',
      'System',
    ])
    admin.wrapper.unmount()

    const viewer = await renderWithApp(AppShell, { me: viewerMe, slots: slot })
    const viewerLinks = viewer.wrapper.findAll('nav a').map((a) => a.text())
    expect(viewerLinks).not.toContain('Users')
    expect(viewerLinks).not.toContain('Audit log')
    expect(viewerLinks).toContain('Sites')
  })

  it('includes extension nav items, respecting their permission', async () => {
    resetExtensions()
    registerNavItem({
      id: 'sso',
      to: '/sso',
      label: 'SSO',
      icon: 'ti ti-key',
      permission: 'users:manage',
      order: 90,
    })
    const viewer = await renderWithApp(AppShell, { me: viewerMe, slots: slot })
    expect(viewer.wrapper.text()).not.toContain('SSO')
    viewer.wrapper.unmount()
    const admin = await renderWithApp(AppShell, { me: adminMe, slots: slot })
    expect(admin.wrapper.findAll('nav a').at(-1)?.text()).toBe('SSO')
    resetExtensions()
  })

  it('toggles the navigation on small screens with aria-expanded', async () => {
    const { wrapper } = await renderWithApp(AppShell, { me: adminMe, slots: slot })
    const toggle = wrapper.get('[data-testid="nav-toggle"]')
    expect(toggle.attributes('aria-expanded')).toBe('false')
    await toggle.trigger('click')
    expect(toggle.attributes('aria-expanded')).toBe('true')
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await flushPromises()
    expect(toggle.attributes('aria-expanded')).toBe('false')
  })

  it('moves focus to the page heading after navigation', async () => {
    const { wrapper, router } = await renderWithApp(AppShell, { me: adminMe, slots: slot })
    await router.push('/sites')
    await flushPromises()
    expect(document.activeElement).toBe(wrapper.get('[data-page-title]').element)
  })

  it('theme toggle offers light, dark and system and reflects the choice', async () => {
    const { wrapper } = await renderWithApp(AppShell, { me: adminMe, slots: slot })
    const theme = useThemeStore()
    await wrapper.get('[data-testid="theme-dark"]').trigger('click')
    expect(theme.preference).toBe('dark')
    expect(wrapper.get('[data-testid="theme-dark"]').attributes('aria-pressed')).toBe('true')
    expect(wrapper.get('[data-testid="theme-light"]').attributes('aria-pressed')).toBe('false')
    await wrapper.get('[data-testid="theme-system"]').trigger('click')
    expect(theme.preference).toBe('system')
  })

  it('user menu opens, closes on Escape and signs out to /login', async () => {
    const api = client as unknown as ReturnType<typeof mockClient>
    api.POST.mockResolvedValue(ok(null, { status: 204 }))
    const { wrapper, router } = await renderWithApp(AppShell, { me: adminMe, slots: slot })
    const trigger = wrapper.get('[data-testid="user-menu"]')
    expect(trigger.attributes('aria-expanded')).toBe('false')
    await trigger.trigger('click')
    expect(trigger.attributes('aria-expanded')).toBe('true')
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await flushPromises()
    expect(trigger.attributes('aria-expanded')).toBe('false')

    await trigger.trigger('click')
    await wrapper.get('[data-testid="sign-out"]').trigger('click')
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('login'))
    expect(useSessionStore().status).toBe('anonymous')
  })
})
