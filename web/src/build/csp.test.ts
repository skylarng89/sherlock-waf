// @vitest-environment node
import { resolve } from 'node:path'
import { build, type Rollup } from 'vite'
import { describe, expect, it } from 'vitest'

// Builds the production bundle in memory (nothing is written to internal/webui/dist)
// and checks the page can run under `Content-Security-Policy: default-src 'self'`.
async function productionBuild() {
  const result = await build({
    configFile: resolve(process.cwd(), 'vite.config.ts'),
    logLevel: 'silent',
    build: { write: false, outDir: resolve(process.cwd(), 'node_modules/.cache/csp-test') },
  })
  const out = (Array.isArray(result) ? result[0] : result) as Rollup.RollupOutput
  return out.output
}

const text = (item: Rollup.OutputAsset | Rollup.OutputChunk): string =>
  item.type === 'chunk' ? item.code : String(item.source)

describe('production build and CSP', () => {
  it('emits an index.html with no inline script, inline handler or external reference', async () => {
    const output = await productionBuild()
    const index = output.find((o) => o.fileName === 'index.html')
    expect(index).toBeDefined()
    const html = text(index as Rollup.OutputAsset)

    const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)]
    expect(scripts.length).toBeGreaterThan(0)
    for (const [, attrs, body] of scripts) {
      expect(attrs).toMatch(/\bsrc="\/assets\//)
      expect(body?.trim()).toBe('')
    }
    expect(html).not.toMatch(/\son[a-z]+\s*=/i)
    expect(html).not.toMatch(/javascript:/i)
    expect(html).not.toMatch(/(?:src|href)="(?:https?:)?\/\//i)
  })

  it('bundles the icon font and references no remote URL from CSS', async () => {
    const output = await productionBuild()
    const css = output
      .filter((o) => o.fileName.endsWith('.css'))
      .map(text)
      .join('\n')
    expect(css).toContain('@font-face')
    expect(css).not.toMatch(/url\(\s*["']?(?:https?:)?\/\//i)
    expect(output.some((o) => /tabler-icons.*\.woff2?$/.test(o.fileName))).toBe(true)
  })
})
