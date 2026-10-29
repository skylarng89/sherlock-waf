import { expect, test } from './fixtures'
import { SESSION_COOKIE } from './lib/api'
import { nextTotp } from './lib/mfa'
import { LoginPage, MfaPage } from './pages/auth'
import { Shell } from './pages/shell'

test.describe('session expiry @smoke', () => {
  test('routes to sign-in with a notice and returns to the intended page', async ({
    adminPage,
    adminContext,
    state,
  }) => {
    const shell = new Shell(adminPage)
    await shell.goto('/tokens', /^API tokens$/)

    // Dropping the cookie is what the browser does when the session cookie expires.
    await adminContext.clearCookies({ name: SESSION_COOKIE })
    await shell.navLink('Sites').click()

    await expect(adminPage).toHaveURL(/\/login\?.*expired=1/)
    await expect(adminPage).toHaveURL(/redirect=(%2F|\/)sites/)
    await expect(
      adminPage.getByText('Your session has expired. Sign in again to continue.'),
    ).toBeVisible()

    const login = new LoginPage(adminPage)
    await login.signIn(state.main.admin.username, state.main.admin.password)
    await expect(adminPage).toHaveURL(/\/login\/mfa/)
    await new MfaPage(adminPage).verify(await nextTotp(state.root, state.main.admin.totpSecret))

    await expect(adminPage).toHaveURL(/\/sites$/)
    await shell.ready('Sites')
  })

  test('a signed-out visitor is sent to sign-in without the expired notice', async ({
    anonPage,
  }) => {
    await anonPage.goto('/sites')
    await expect(anonPage).toHaveURL(/\/login/)
    await expect(anonPage.getByText('Your session has expired.')).toHaveCount(0)
  })
})
