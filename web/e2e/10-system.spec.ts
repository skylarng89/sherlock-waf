import { expect, test } from './fixtures'
import { expectAccessible } from './lib/axe'
import { Shell } from './pages/shell'

test.describe('system page', () => {
  test('shows update status (or a graceful reason) and the backup list', async ({
    adminPage,
  }, testInfo) => {
    await new Shell(adminPage).goto('/system', /^System$/)

    const updates = adminPage.getByTestId('update-section')
    await expect(updates.getByRole('heading', { name: 'Updates' })).toBeVisible()
    await updates.getByTestId('update-check').click()
    // The e2e node may have no release server: either a status or a plain-language reason is fine,
    // an error toast or an alert is not.
    await expect(updates.locator('dl, [data-testid="update-problem"]').first()).toBeVisible()
    await expect(adminPage.getByRole('alert')).toHaveCount(0)

    await expect(adminPage.getByRole('heading', { name: 'Backups' })).toBeVisible()
    await expectAccessible(adminPage, testInfo, 'system updates and backups')
  })
})
