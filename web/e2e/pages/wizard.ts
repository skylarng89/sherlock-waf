import { expect } from '@playwright/test'
import { Shell } from './shell'

export class SetupPage extends Shell {
  token = this.page.getByLabel('Setup token')
  username = this.page.getByLabel('Username')
  password = this.page.getByLabel(/^Password\b/)
  confirm = this.page.getByLabel('Confirm password')
  submit = this.page.getByRole('button', { name: 'Create administrator' })

  async createAdmin(token: string, username: string, password: string): Promise<void> {
    await this.token.fill(token)
    await this.username.fill(username)
    await this.password.fill(password)
    await this.confirm.fill(password)
    await this.submit.click()
  }
}

export class WizardPage extends Shell {
  async skipAdminHostname(): Promise<void> {
    await expect(
      this.page.getByRole('heading', { name: 'Admin hostname (optional)' }),
    ).toBeVisible()
    await this.page.getByRole('button', { name: 'Skip this step' }).click()
  }

  async addFirstSite(site: { name: string; host: string; target: string }): Promise<void> {
    await expect(this.page.getByRole('heading', { name: 'Add your first site' })).toBeVisible()
    await this.page.getByLabel('Display name').fill(site.name)
    await this.page.getByLabel('Public hostname').fill(site.host)
    await this.page.getByLabel('Upstream address').fill(site.target)
    await this.page.getByRole('button', { name: 'Test connection' }).click()
    await expect(this.page.getByTestId('test-ok')).toBeVisible()
    await this.page.getByLabel('TLS mode').selectOption('none')
    await this.page.getByRole('button', { name: 'Add site' }).click()
    await expect(this.page.getByRole('heading', { name: 'Setup complete' })).toBeVisible()
  }
}
