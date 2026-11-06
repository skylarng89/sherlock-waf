import { expect, type Locator, type Page } from '@playwright/test'
import { Shell } from './shell'

/** The Login protection and Data protection site tabs (M11-T3). */
export class LoginProtectionPage extends Shell {
  static readonly path = '/sites/demo/login-protection'
  readonly addEndpoint: Locator
  readonly save: Locator
  readonly perUsername: Locator

  constructor(page: Page) {
    super(page)
    this.addEndpoint = page.getByRole('button', { name: 'Add endpoint' })
    this.save = page.getByRole('button', { name: 'Save', exact: true })
    this.perUsername = page.getByLabel(/^Failures per username/)
  }

  async open(): Promise<void> {
    await this.goto(LoginProtectionPage.path, /Demo shop/)
    await expect(this.page.getByRole('heading', { name: 'Login protection' })).toBeVisible()
  }
}

export class DataProtectionPage extends Shell {
  static readonly path = '/sites/demo/data-protection'
  readonly addPattern: Locator
  readonly save: Locator
  readonly maxBody: Locator

  constructor(page: Page) {
    super(page)
    this.addPattern = page.getByRole('button', { name: 'Add pattern' })
    this.save = page.getByRole('button', { name: 'Save', exact: true })
    this.maxBody = page.getByLabel(/^Largest response scanned/)
  }

  async open(): Promise<void> {
    await this.goto(DataProtectionPage.path, /Demo shop/)
    await expect(this.page.getByRole('heading', { name: 'Data protection' })).toBeVisible()
  }
}
