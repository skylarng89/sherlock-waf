import { expect } from '@playwright/test'
import { Shell } from './shell'

export class LoginPage extends Shell {
  username = this.page.getByLabel('Username')
  password = this.page.getByLabel(/^Password\b/)
  submit = this.page.getByRole('button', { name: 'Sign in' })

  async open(query = ''): Promise<void> {
    await this.goto(`/login${query}`, 'Sign in')
  }

  // The server allows 5 sign-in attempts a minute per client address, and a whole
  // suite signs in from one address, so a throttled attempt waits out the
  // countdown the page shows and tries again instead of failing the test.
  async signIn(username: string, password: string): Promise<void> {
    for (let attempt = 0; attempt < 4; attempt++) {
      await this.username.fill(username)
      await this.password.fill(password)
      await this.submit.click()
      const throttled = this.page.getByText(
        /Too many sign-in attempts|You can try signing in again now/,
      )
      const left = this.page
        .waitForURL((u) => !u.pathname.startsWith('/login') || u.pathname !== '/login', {
          timeout: 15_000,
        })
        .then(() => 'left')
      const blocked = throttled
        .first()
        .waitFor({ timeout: 15_000 })
        .then(() => 'blocked')
      if ((await Promise.race([left, blocked]).catch(() => 'left')) === 'left') return
      await this.page.getByText('You can try signing in again now.').waitFor({ timeout: 90_000 })
    }
  }
}

export class MfaPage extends Shell {
  code = this.page.getByLabel('Authentication code')

  async verify(code: string): Promise<void> {
    await expect(this.heading).toHaveText('Two-step verification')
    await this.code.fill(code)
    await this.page.getByRole('button', { name: 'Verify' }).click()
  }
}

export class EnrolPage extends Shell {
  code = this.page.getByLabel('Confirmation code')

  /** Reads the manual-entry key once it is displayed and checks the QR code renders. */
  async secret(): Promise<string> {
    await expect(this.heading).toHaveText('Set up two-step verification')
    await expect(
      this.page.getByRole('img', { name: 'QR code for your authenticator app' }),
    ).toBeVisible()
    const secret = this.page.getByTestId('secret')
    await expect(secret).toHaveText(/[A-Z2-7]{4}/)
    return ((await secret.textContent()) ?? '').replace(/\s+/g, '')
  }

  async confirm(code: string): Promise<void> {
    await this.code.fill(code)
    await this.page.getByRole('button', { name: 'Confirm and sign in' }).click()
  }
}
