import { expect, test } from './fixtures'
import { LoginPage } from './pages/auth'
import { Shell } from './pages/shell'
import type { Page } from '@playwright/test'

const INTERACTIVE =
  'a[href], button, input, select, textarea, [tabindex="0"], summary, [contenteditable="true"]'

/** Tags visible, enabled interactive elements in DOM order and returns their count. */
async function tagInteractive(page: Page): Promise<number> {
  return page.evaluate((selector) => {
    document.querySelectorAll('[data-e2e-idx]').forEach((el) => el.removeAttribute('data-e2e-idx'))
    let n = 0
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(selector))) {
      const style = getComputedStyle(el)
      const hidden =
        style.visibility === 'hidden' ||
        style.display === 'none' ||
        el.closest('[inert]') !== null ||
        el.closest('dialog:not([open])') !== null ||
        (el as HTMLButtonElement).disabled ||
        el.getBoundingClientRect().width === 0
      // The skip link is clipped (sr-only) until focused, so it is judged by its class.
      if (hidden && !el.classList.contains('sr-only')) continue
      if (el.offsetParent === null && style.position !== 'fixed') continue
      el.setAttribute('data-e2e-idx', String(n++))
    }
    return n
  }, INTERACTIVE)
}

async function tabThrough(page: Page, count: number): Promise<number[]> {
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur())
  const order: number[] = []
  for (let i = 0; i < count; i++) {
    await page.keyboard.press('Tab')
    const idx = await page.evaluate(() =>
      Number(document.activeElement?.getAttribute('data-e2e-idx') ?? -1),
    )
    order.push(idx)
  }
  return order
}

test.describe('keyboard @smoke', () => {
  test('sign-in page: every control is reachable in reading order', async ({ anonPage }) => {
    const login = new LoginPage(anonPage)
    await login.open()
    const count = await tagInteractive(anonPage)
    expect(count).toBeGreaterThanOrEqual(5) // skip link, 3 theme buttons, 2 inputs, submit
    const order = await tabThrough(anonPage, count)
    expect(order).toEqual(Array.from({ length: count }, (_, i) => i))
    const names = await anonPage.evaluate(() =>
      Array.from(document.querySelectorAll('[data-e2e-idx]')).map((e) =>
        (e.getAttribute('aria-label') ?? e.textContent ?? '').trim().slice(0, 30),
      ),
    )
    // Content order: username precedes password precedes the submit button.
    expect(names.join('|')).toMatch(/Skip to content.*Light.*Dark.*System.*Sign in$/)
    await expect(login.username).toBeVisible()
  })

  test('sites list: every control is reachable and the skip link works', async ({ adminPage }) => {
    const shell = new Shell(adminPage)
    await shell.goto('/sites', /^Sites$/)
    const count = await tagInteractive(adminPage)
    const order = await tabThrough(adminPage, count)
    expect(order).toEqual(Array.from({ length: count }, (_, i) => i))

    // Reload so sequential focus navigation restarts at the top of the document.
    await shell.goto('/sites', /^Sites$/)
    await adminPage.keyboard.press('Tab')
    const skip = adminPage.getByRole('link', { name: 'Skip to content' })
    await expect(skip).toBeFocused()
    await expect(skip).toBeVisible()
    await adminPage.keyboard.press('Enter')
    await expect(adminPage.locator('#main')).toBeInViewport()
    // The next Tab lands inside main, not back in the navigation.
    await adminPage.keyboard.press('Tab')
    const inMain = await adminPage.evaluate(
      () => document.getElementById('main')?.contains(document.activeElement) ?? false,
    )
    expect(inMain).toBe(true)
  })

  test('dialogs trap focus, Esc closes and focus returns to the opener', async ({ adminPage }) => {
    const shell = new Shell(adminPage)
    await shell.goto('/sites/demo', /Demo shop/)
    const opener = adminPage.getByRole('button', { name: 'Delete site' })
    await opener.focus()
    await adminPage.keyboard.press('Enter')
    const dialog = adminPage.getByRole('dialog', { name: 'Delete demo?' })
    await expect(dialog).toBeVisible()
    // Typed-confirmation dialogs start in the input.
    await expect(dialog.getByLabel(/Type demo to confirm/)).toBeFocused()

    for (let i = 0; i < 6; i++) {
      await adminPage.keyboard.press('Tab')
      const inside = await adminPage.evaluate(() => {
        // Leaving the page entirely (to browser chrome) leaves body focused; that is not a leak.
        const active = document.activeElement
        return (
          active === document.body ||
          (document.querySelector('dialog[open]')?.contains(active) ?? false)
        )
      })
      expect(inside, `focus never reached the page behind the dialog after Tab ${i + 1}`).toBe(true)
    }
    await adminPage.keyboard.press('Escape')
    await expect(dialog).toBeHidden()
    await expect(opener).toBeFocused()

    // The block confirmation: initial focus is Cancel.
    const mode = adminPage.getByLabel('Change mode')
    await mode.focus()
    await mode.selectOption('block')
    const block = adminPage.getByRole('dialog', { name: /to block mode/ })
    await expect(block.getByRole('button', { name: 'Cancel' })).toBeFocused()
    await adminPage.keyboard.press('Escape')
    await expect(block).toBeHidden()
    await expect(mode).toBeFocused()
  })
})
