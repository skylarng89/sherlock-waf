import { defineConfig, devices } from '@playwright/test'

// One worker and no file-level parallelism: the specs share one bootstrapped node and
// the TOTP replay rule means sign-ins for one secret must be sequential.
export default defineConfig({
  testDir: '.',
  testMatch: '**/*.spec.ts',
  outputDir: './test-results',
  globalSetup: './global-setup.ts',
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  timeout: 90_000,
  expect: { timeout: 10_000 },
  reporter: [['list'], ['html', { open: 'never', outputFolder: './playwright-report' }]],
  use: {
    ...devices['Desktop Chrome'],
    ignoreHTTPSErrors: true,
    locale: 'en-US',
    // The dashboard honours prefers-reduced-motion, which keeps chart and dialog
    // animations out of axe and screenshot timing.
    reducedMotion: 'reduce',
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
})
