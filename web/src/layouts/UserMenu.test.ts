import { describe, expect, it } from 'vitest'
import { renderWithApp, viewerMe } from '@/test-utils'
import UserMenu from './UserMenu.vue'

describe('UserMenu', () => {
  it('links to the account page for a full session', async () => {
    const { wrapper } = await renderWithApp(UserMenu, { me: viewerMe })
    await wrapper.get('[data-testid="user-menu"]').trigger('click')
    const link = wrapper.get('[data-testid="account-link"]')
    expect(link.text()).toContain('Account')
    expect(link.attributes('href')).toBe('/account')
  })

  it('is absent without a full session, so pre-MFA users never see the account entry', async () => {
    const { wrapper } = await renderWithApp(UserMenu, {})
    expect(wrapper.find('[data-testid="user-menu"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="account-link"]').exists()).toBe(false)
  })
})
