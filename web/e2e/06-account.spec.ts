import { expect, test } from './fixtures'
import { nextTotp } from './lib/mfa'
import { EnrolPage, LoginPage, MfaPage } from './pages/auth'
import { Shell } from './pages/shell'

test.describe('account', () => {
  test('a user changes their own password, signs out and signs in with the new one', async ({
    adminPage,
    anonPage,
    state,
  }) => {
    const username = 'e2e-account'
    const oldPassword = 'account passphrase 123'
    const newPassword = 'account passphrase 456'

    await test.step('admin creates the user', async () => {
      await new Shell(adminPage).goto('/users', /^Users$/)
      await adminPage.getByLabel(/^Username/).fill(username)
      await adminPage.getByLabel(/^Initial password/).fill(oldPassword)
      await adminPage.getByLabel(/^Role/).selectOption('viewer')
      await adminPage.getByRole('button', { name: 'Create user' }).click()
      await expect(adminPage.getByTestId(`user-${username}`)).toBeVisible()
    })

    let secret = ''
    await test.step('the user signs in and enrols an authenticator', async () => {
      const login = new LoginPage(anonPage)
      await login.open()
      await login.signIn(username, oldPassword)
      await expect(anonPage).toHaveURL(/\/login\/enrol/)
      const enrol = new EnrolPage(anonPage)
      secret = await enrol.secret()
      await enrol.confirm(await nextTotp(state.root, secret))
      await expect(anonPage).toHaveURL(/\/$/)
    })

    const shell = new Shell(anonPage)
    await test.step('the account page is reached from the account menu', async () => {
      await anonPage.getByTestId('user-menu').click()
      await anonPage.getByTestId('account-link').click()
      await shell.ready(/^Account$/)
    })

    await test.step('the password changes and the user stays signed in', async () => {
      await anonPage.getByLabel(/^Current password/).fill(oldPassword)
      await anonPage.getByLabel(/^New password/).fill(newPassword)
      await anonPage.getByLabel(/^Confirm new password/).fill(newPassword)
      await anonPage.getByRole('button', { name: 'Change password' }).click()
      await expect(shell.toast(/Password changed/)).toBeVisible()
      await expect(shell.heading).toHaveText(/^Account$/)
      await expect(anonPage.getByTestId('session-current')).toBeVisible()
    })

    await test.step('the user signs out and back in with the new password', async () => {
      await shell.signOut()
      const login = new LoginPage(anonPage)
      await login.open()
      await login.signIn(username, newPassword)
      await new MfaPage(anonPage).verify(await nextTotp(state.root, secret))
      await expect(anonPage).toHaveURL(/\/$/)
    })
  })
})
