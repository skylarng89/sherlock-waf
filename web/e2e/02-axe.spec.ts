import { adminApi, expect, test } from './fixtures'
import { expectAccessible } from './lib/axe'
import { EnrolPage, LoginPage, MfaPage } from './pages/auth'
import { Shell } from './pages/shell'

const THEMES = ['light', 'dark'] as const

// Pages reachable by the signed-in administrator. `:version` is resolved at run time.
const ADMIN_PAGES: { name: string; path: string; title: RegExp }[] = [
  { name: 'overview', path: '/', title: /^Overview$/ },
  { name: 'sites', path: '/sites', title: /^Sites$/ },
  { name: 'site-create', path: '/sites/new', title: /^Add site$/ },
  { name: 'site-settings', path: '/sites/demo', title: /Demo shop/ },
  { name: 'site-endpoints', path: '/sites/demo/endpoints', title: /Demo shop|^Endpoints$/ },
  { name: 'endpoint-create', path: '/sites/demo/endpoints/new', title: /Demo shop|Add endpoint/ },
  { name: 'defaults', path: '/defaults', title: /defaults/i },
  { name: 'certificates', path: '/certificates', title: /^Certificates$/ },
  { name: 'block-pages', path: '/certificates/block-pages', title: /block page/i },
  { name: 'users', path: '/users', title: /^Users$/ },
  { name: 'tokens', path: '/tokens', title: /^API tokens$/ },
  { name: 'audit', path: '/audit', title: /audit/i },
  { name: 'history', path: '/history', title: /history/i },
  { name: 'history-detail', path: '/history/:version', title: /./ },
  { name: 'forbidden', path: '/403', title: /^Access denied$/ },
  { name: 'not-found', path: '/no-such-page', title: /^Page not found$/ },
]

test.describe('axe: signed-in pages', () => {
  for (const theme of THEMES) {
    test(`all admin pages, ${theme} theme`, async ({ adminPage, state }, testInfo) => {
      test.setTimeout(240_000)
      const shell = new Shell(adminPage)
      const api = await adminApi(state)
      const versions = await api.json<{ items: { id: string }[] }>(
        await api.get('/config/versions'),
      )
      await api.dispose()
      const version = versions.items[0]?.id ?? ''
      expect(version).not.toBe('')

      await shell.goto('/', /^Overview$/)
      await shell.setTheme(theme)
      const failures: string[] = []
      for (const p of ADMIN_PAGES) {
        await test.step(`${p.name}`, async () => {
          try {
            await shell.goto(p.path.replace(':version', version), p.title)
            await expectAccessible(adminPage, testInfo, `${p.name}-${theme}`)
          } catch (e) {
            failures.push(`${p.name} (${theme}): ${(e as Error).message}`)
          }
        })
      }
      expect(failures, failures.join('\n\n')).toEqual([])
    })
  }
})

test.describe('axe: sign-in pages', () => {
  for (const theme of THEMES) {
    test(`login, MFA and enrolment, ${theme} theme`, async ({ anonPage, state }, testInfo) => {
      test.setTimeout(120_000)
      // A user without an authenticator to reach the enrolment page.
      const username = `axe-enrol-${theme}`
      const password = 'another long passphrase 7'
      const api = await adminApi(state)
      const created = await api.post('/users', { username, password, role: 'viewer' })
      expect([201, 409]).toContain(created.status())
      await api.dispose()

      const login = new LoginPage(anonPage)
      await login.open()
      await login.setTheme(theme)
      await expectAccessible(anonPage, testInfo, `login-${theme}`)

      await login.signIn(state.main.admin.username, state.main.admin.password)
      await expect(anonPage).toHaveURL(/\/login\/mfa/)
      const mfa = new MfaPage(anonPage)
      await mfa.ready('Two-step verification')
      await expectAccessible(anonPage, testInfo, `mfa-${theme}`)

      await anonPage.context().clearCookies()
      await login.open()
      await login.signIn(username, password)
      await expect(anonPage).toHaveURL(/\/login\/enrol/)
      const enrol = new EnrolPage(anonPage)
      await enrol.secret()
      await expectAccessible(anonPage, testInfo, `enrol-${theme}`)
    })
  }
})

test.describe('axe: dialogs', () => {
  for (const theme of THEMES) {
    test(`confirm dialog and token secret dialog, ${theme} theme`, async ({
      adminPage,
    }, testInfo) => {
      const shell = new Shell(adminPage)
      await shell.goto('/sites/demo', /Demo shop/)
      await shell.setTheme(theme)
      await adminPage.getByLabel('Change mode').selectOption('block')
      const confirm = adminPage.getByRole('dialog', { name: /Switch Demo shop to block mode/ })
      await expect(confirm).toBeVisible()
      await expectAccessible(adminPage, testInfo, `confirm-dialog-${theme}`)
      await confirm.getByRole('button', { name: 'Cancel' }).click()
      await expect(confirm).toBeHidden()

      await shell.goto('/tokens', /^API tokens$/)
      await adminPage.getByLabel(/^Name/).fill(`axe-${theme}`)
      await adminPage.getByLabel(/^Read/).check()
      await adminPage.getByRole('button', { name: 'Create token' }).click()
      const secret = adminPage.getByRole('dialog', { name: 'Copy your new token' })
      await expect(secret).toBeVisible()
      await expectAccessible(adminPage, testInfo, `token-secret-dialog-${theme}`)
      await secret.getByRole('button', { name: 'I have stored it' }).click()
      await expect(secret).toBeHidden()
    })
  }
})
