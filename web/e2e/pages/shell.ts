import { expect, type Locator, type Page } from '@playwright/test'

/** Behaviour shared by every page: the shell, headings, toasts and the theme toggle. */
export class Shell {
  readonly heading: Locator

  constructor(readonly page: Page) {
    this.heading = page.locator('h1[data-page-title]')
  }

  /** Waits until the route rendered its heading and nothing says "Loading". */
  async ready(title?: string | RegExp): Promise<void> {
    await expect(this.heading).toBeVisible()
    if (title) await expect(this.heading).toHaveText(title)
    await expect(this.page.getByText(/^Loading/)).toHaveCount(0)
  }

  async goto(path: string, title?: string | RegExp): Promise<void> {
    await this.page.goto(path)
    await this.ready(title)
  }

  async setTheme(theme: 'light' | 'dark'): Promise<void> {
    await this.page.getByTestId(`theme-${theme}`).click()
    await expect(this.page.locator('html')).toHaveClass(theme === 'dark' ? /dark/ : /^(?!.*dark)/)
  }

  navLink(name: string | RegExp): Locator {
    return this.page
      .getByRole('navigation', { name: 'Main navigation' })
      .getByRole('link', { name })
  }

  toast(text: string | RegExp): Locator {
    return this.page.getByRole('region', { name: 'Notifications' }).getByText(text)
  }

  async signOut(): Promise<void> {
    await this.page.getByTestId('user-menu').click()
    await this.page.getByTestId('sign-out').click()
    await expect(this.page).toHaveURL(/\/login/)
  }
}
