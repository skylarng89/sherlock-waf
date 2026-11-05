import AxeBuilder from '@axe-core/playwright'
import { expect, type Page, type TestInfo } from '@playwright/test'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice']

export interface AxeSummary {
  blocking: string[]
  minor: string[]
}

function describe(v: {
  id: string
  impact?: string | null
  help: string
  nodes: { target: unknown[] }[]
}): string {
  const targets = v.nodes.map((n) => n.target.join(' ')).join(' | ')
  return `${v.id} [${v.impact ?? 'n/a'}] ${v.help} -> ${targets}`
}

/**
 * Runs axe on the page's current state. Serious and critical violations fail the test;
 * moderate and minor ones are attached to the report so they stay visible.
 */
export async function expectAccessible(
  page: Page,
  testInfo: TestInfo,
  label: string,
  include?: string,
): Promise<AxeSummary> {
  let builder = new AxeBuilder({ page }).withTags(TAGS)
  if (include) builder = builder.include(include)
  const { violations } = await builder.analyze()
  const blocking = violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map(describe)
  const minor = violations
    .filter((v) => v.impact !== 'serious' && v.impact !== 'critical')
    .map(describe)
  if (minor.length > 0) {
    await testInfo.attach(`axe-minor-${label}`, {
      body: minor.join('\n'),
      contentType: 'text/plain',
    })
    console.log(`[axe minor] ${label}\n  ${minor.join('\n  ')}`)
  }
  expect(blocking, `serious/critical axe violations on ${label}`).toEqual([])
  return { blocking, minor }
}
