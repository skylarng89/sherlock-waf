import { adminApi, expect, test } from './fixtures'
import { expectAccessible } from './lib/axe'
import { Shell } from './pages/shell'

const WEBHOOK = {
  url: 'https://siem.example.test/ingest?token=e2e-secret-token',
  hmac_secret: 'e2e-hmac-secret-0123456789abcdef0123',
}

test.describe('exporters, channels and alerts', () => {
  test('an exporter is created, never shows its secrets again, and can be deleted', async ({
    adminPage: page,
    state,
  }, testInfo) => {
    const api = await adminApi(state)
    await api.delete('/exporters/e2e-siem')
    const shell = new Shell(page)
    await shell.goto('/integrations/exporters', /^Exporters$/)

    await page.getByTestId('exporter-add').click()
    const dialog = page.getByRole('dialog', { name: 'Add exporter' })
    await dialog.getByLabel(/^Name/).fill('E2E SIEM')
    await dialog.getByLabel(/^Type/).selectOption('webhook')
    await dialog.getByLabel(/^URL/).fill(WEBHOOK.url)
    await dialog.getByLabel(/^Signing secret/).fill(WEBHOOK.hmac_secret)
    await dialog.getByRole('button', { name: 'Save' }).click()

    const row = page.getByTestId('exporter-e2e-siem')
    await expect(row).toBeVisible()
    await expect(shell.toast(/E2E SIEM saved/)).toBeVisible()
    await expectAccessible(page, testInfo, 'exporters list')

    // Secrets come back masked in the API and never reach the page.
    const listed = await (await api.get('/exporters')).text()
    expect(listed).not.toContain('e2e-secret-token')
    expect(listed).not.toContain(WEBHOOK.hmac_secret)
    await page.reload()
    await expect(page.getByTestId('exporter-e2e-siem')).toBeVisible()
    await expect(page.locator('body')).not.toContainText('e2e-secret-token')

    // Editing without retyping keeps the stored secret.
    await row.getByRole('button', { name: 'Edit E2E SIEM' }).click()
    const edit = page.getByRole('dialog', { name: 'Edit exporter' })
    await expect(edit.getByLabel(/^Signing secret/)).toHaveAttribute('placeholder', 'unchanged')
    await edit.getByLabel(/^Name/).fill('E2E SIEM renamed')
    await edit.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByTestId('exporter-e2e-siem')).toContainText('E2E SIEM renamed')

    await page.getByRole('button', { name: 'Delete E2E SIEM renamed' }).click()
    await page
      .getByRole('dialog', { name: /Delete E2E SIEM renamed/ })
      .getByRole('button', { name: 'Delete' })
      .click()
    await expect(page.getByTestId('exporter-e2e-siem')).toHaveCount(0)
  })

  test('a channel in use cannot be deleted, and the alert page links to channels when empty', async ({
    adminPage: page,
    state,
  }, testInfo) => {
    const api = await adminApi(state)
    await api.delete('/alert-rules/e2e-drops')
    await api.delete('/notification-channels/e2e-ops')
    const shell = new Shell(page)

    await shell.goto('/integrations/alerts', /^Alerts$/)
    await page.getByTestId('alert-add').click()
    await expect(page.getByTestId('no-channels').getByRole('link')).toHaveAttribute(
      'href',
      '/integrations/channels',
    )
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click()

    const channel = await api.put('/notification-channels/e2e-ops', {
      name: 'E2E Ops',
      type: 'slack',
      enabled: true,
      settings: { url: 'https://hooks.example.test/services/T/B/secret' },
    })
    expect(channel.status()).toBe(200)

    await page.reload()
    await page.getByTestId('alert-add').click()
    const dialog = page.getByRole('dialog', { name: 'Add alert rule' })
    await dialog.getByLabel(/^Name/).fill('E2E drops')
    await dialog.getByLabel(/^Condition/).selectOption('events_dropped')
    await dialog.getByLabel('E2E Ops').check()
    await dialog.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByTestId('alert-e2e-drops')).toBeVisible()
    await expectAccessible(page, testInfo, 'alerts list')

    await shell.goto('/integrations/channels', /^Notification channels$/)
    await page.getByRole('button', { name: 'Delete E2E Ops' }).click()
    await page
      .getByRole('dialog', { name: /Delete E2E Ops/ })
      .getByRole('button', { name: 'Delete' })
      .click()
    await expect(page.getByTestId('page-error')).toContainText('E2E drops')
    await expect(page.getByTestId('channel-e2e-ops')).toBeVisible()

    await api.delete('/alert-rules/e2e-drops')
    await api.delete('/notification-channels/e2e-ops')
  })
})
