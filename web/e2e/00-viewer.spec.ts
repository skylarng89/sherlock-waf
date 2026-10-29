import { expect, test } from './fixtures'
import { nextTotp } from './lib/mfa'
import { CSRF_COOKIE } from './lib/api'
import { EnrolPage, LoginPage } from './pages/auth'
import { Shell } from './pages/shell'

test.describe('viewer role', () => {
  test('is created by an admin, signs in with MFA enrolment and cannot write', async ({
    adminPage,
    anonPage,
    state,
  }) => {
    const username = 'e2e-viewer'
    const password = 'viewer passphrase 123'

    await test.step('admin creates the viewer on the Users page', async () => {
      await new Shell(adminPage).goto('/users', /^Users$/)
      await adminPage.getByLabel(/^Username/).fill(username)
      await adminPage.getByLabel(/^Initial password/).fill(password)
      await adminPage.getByLabel(/^Role/).selectOption('viewer')
      await adminPage.getByRole('button', { name: 'Create user' }).click()
      await expect(adminPage.getByTestId(`user-${username}`)).toBeVisible()
    })

    await test.step('the viewer signs in and enrols an authenticator', async () => {
      const login = new LoginPage(anonPage)
      await login.open()
      await login.signIn(username, password)
      await expect(anonPage).toHaveURL(/\/login\/enrol/)
      const enrol = new EnrolPage(anonPage)
      const secret = await enrol.secret()
      await enrol.confirm(await nextTotp(state.root, secret))
      await expect(anonPage).toHaveURL(/\/$/)
    })

    const shell = new Shell(anonPage)
    await test.step('write controls are absent on the sites pages', async () => {
      await shell.goto('/sites', /^Sites$/)
      await expect(anonPage.getByRole('button', { name: 'Add site' })).toHaveCount(0)
      await expect(shell.navLink('Users')).toHaveCount(0)

      await anonPage.getByRole('link', { name: 'Demo shop' }).click()
      await shell.ready(/Demo shop/)
      await expect(anonPage.getByText('You have read-only access')).toBeVisible()
      await expect(anonPage.getByLabel('Change mode')).toHaveCount(0)
      await expect(anonPage.getByRole('button', { name: 'Save' })).toHaveCount(0)
      await expect(anonPage.getByRole('button', { name: 'Delete site' })).toHaveCount(0)
      await expect(anonPage.getByLabel(/^Display name/)).toBeDisabled()

      await shell.goto('/sites/new')
      await expect(shell.heading).toHaveText('Access denied')
    })

    await test.step('the Users page is forbidden', async () => {
      await anonPage.goto('/users')
      await shell.ready('Access denied')
      await expect(anonPage.getByRole('link', { name: 'Go to the overview' })).toBeVisible()
    })

    await test.step('a direct API write is refused with 403', async () => {
      const cookies = await anonPage.context().cookies()
      const csrf = cookies.find((c) => c.name === CSRF_COOKIE)?.value ?? ''
      const res = await anonPage.request.post('/api/v1/sites', {
        headers: { 'X-CSRF-Token': csrf },
        data: {
          id: 'viewer-attempt',
          hosts: ['v.e2e.test'],
          upstreams: { targets: ['127.0.0.1:9'] },
        },
      })
      expect(res.status()).toBe(403)
      const users = await anonPage.request.post('/api/v1/users', {
        headers: { 'X-CSRF-Token': csrf },
        data: { username: 'sneaky-user', password: 'sneaky passphrase 1', role: 'admin' },
      })
      expect(users.status()).toBe(403)
      // Reads they are entitled to still work.
      expect((await anonPage.request.get('/api/v1/sites')).status()).toBe(200)
    })
  })
})
