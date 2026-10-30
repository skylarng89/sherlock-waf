import { expect, test } from './fixtures'
import type { Locator, Page } from '@playwright/test'
import { Shell } from './pages/shell'

/** The message element a control points at through aria-describedby ("...-error"). */
async function describedError(control: Locator): Promise<Locator> {
  const ids = ((await control.getAttribute('aria-describedby')) ?? '').split(/\s+/)
  const errorId = ids.find((id) => id.endsWith('-error'))
  expect(errorId, 'control references an error element through aria-describedby').toBeTruthy()
  return control.page().locator(`[id="${errorId}"]`)
}

async function expectFieldError(control: Locator, message: string | RegExp): Promise<void> {
  await expect(control).toHaveAttribute('aria-invalid', 'true')
  await expect(await describedError(control)).toContainText(message)
}

async function fillSite(
  page: Page,
  site: { id: string; hosts: string; targets: string },
): Promise<void> {
  await page.getByLabel(/^Site ID/).fill(site.id)
  await page.getByLabel(/^Hostnames/).fill(site.hosts)
  await page.getByLabel(/^Upstream targets/).fill(site.targets)
}

test.describe('form errors land on fields (acceptance criterion 4) @smoke', () => {
  test('server validation messages appear next to hostnames and upstream targets', async ({
    adminPage: page,
  }) => {
    await new Shell(page).goto('/sites/new', /^Add site$/)
    await fillSite(page, { id: 'e2e-invalid', hosts: 'bad host_name!', targets: 'not a target' })

    const response = page.waitForResponse(
      (r) => r.request().method() !== 'GET' && r.url().includes('/api/v1/') && r.status() === 422,
    )
    await page.getByRole('button', { name: 'Create site' }).click()
    const body = (await (await response).json()) as {
      errors: { path: string; message: string }[]
    }
    expect(body.errors.length).toBeGreaterThan(0)

    const hosts = page.getByLabel(/^Hostnames/)
    const targets = page.getByLabel(/^Upstream targets/)
    for (const err of body.errors) {
      if (/hosts/.test(err.path)) await expectFieldError(hosts, err.message)
      else if (/targets/.test(err.path)) await expectFieldError(targets, err.message)
    }
    // Both offending fields are flagged, and the untouched id field is not.
    await expect(hosts).toHaveAttribute('aria-invalid', 'true')
    await expect(targets).toHaveAttribute('aria-invalid', 'true')
    await expect(page.getByLabel(/^Site ID/)).not.toHaveAttribute('aria-invalid', 'true')
    await expect(page).toHaveURL(/\/sites\/new$/)
  })

  test('a duplicate id is reported on the id field', async ({ adminPage: page }) => {
    await new Shell(page).goto('/sites/new', /^Add site$/)
    await fillSite(page, { id: 'demo', hosts: 'dup.e2e.test', targets: '127.0.0.1:9' })
    await page.getByRole('button', { name: 'Create site' }).click()
    await expectFieldError(page.getByLabel(/^Site ID/), 'A site with this ID already exists')
  })

  test('a malformed id is rejected on the id field before submitting', async ({
    adminPage: page,
  }) => {
    await new Shell(page).goto('/sites/new', /^Add site$/)
    await fillSite(page, { id: 'Not_Valid', hosts: 'ok.e2e.test', targets: '127.0.0.1:9' })
    await page.getByRole('button', { name: 'Create site' }).click()
    await expectFieldError(page.getByLabel(/^Site ID/), 'Use lowercase letters')
  })
})
