import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const css = readFileSync(resolve(process.cwd(), 'src/styles/main.css'), 'utf8')

function tokens(selector: string): Record<string, string> {
  const block = new RegExp(`${selector.replace('.', '\\.')}\\s*\\{([^}]*)\\}`).exec(css)?.[1] ?? ''
  const out: Record<string, string> = {}
  for (const m of block.matchAll(/--sk-([\w-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)) {
    out[m[1] as string] = m[2] as string
  }
  return out
}

function luminance(hex: string): number {
  const channel = (i: number) => {
    const c = parseInt(hex.slice(1 + i * 2, 3 + i * 2), 16) / 255
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  }
  return 0.2126 * channel(0) + 0.7152 * channel(1) + 0.0722 * channel(2)
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number]
  return (hi + 0.05) / (lo + 0.05)
}

// [foreground token, background token] pairs actually used by components and pages.
const TEXT_PAIRS: [string, string][] = [
  ['text', 'bg'],
  ['text', 'surface'],
  ['text', 'surface-muted'],
  ['muted', 'bg'],
  ['muted', 'surface'],
  ['muted', 'surface-muted'],
  ['accent', 'bg'],
  ['accent', 'surface'],
  ['accent-contrast', 'accent'],
  ['accent-contrast', 'accent-hover'],
  ['accent-contrast', 'danger'],
  ['danger', 'surface'],
  ['danger', 'danger-bg'],
  ['warning', 'surface'],
  ['warning', 'warning-bg'],
  ['success', 'surface'],
  ['success', 'success-bg'],
  ['info', 'surface'],
  ['info', 'info-bg'],
]

// Non-text boundaries: input borders and the focus ring (WCAG 1.4.11).
const UI_PAIRS: [string, string][] = [
  ['border-strong', 'surface'],
  ['border-strong', 'bg'],
  ['focus', 'surface'],
  ['focus', 'bg'],
]

describe.each([
  ['light', ':root'],
  ['dark', '.dark'],
])('%s theme tokens', (_name, selector) => {
  const t = tokens(selector)

  it('defines every token the pairs reference', () => {
    for (const key of [...TEXT_PAIRS, ...UI_PAIRS].flat()) expect(t[key], key).toBeDefined()
  })

  it.each(TEXT_PAIRS)('text %s on %s is at least 4.5:1', (fg, bg) => {
    expect(contrast(t[fg] as string, t[bg] as string)).toBeGreaterThanOrEqual(4.5)
  })

  it.each(UI_PAIRS)('boundary %s against %s is at least 3:1', (fg, bg) => {
    expect(contrast(t[fg] as string, t[bg] as string)).toBeGreaterThanOrEqual(3)
  })
})

describe('contrast()', () => {
  it('matches the WCAG reference values', () => {
    expect(contrast('#000000', '#ffffff')).toBeCloseTo(21, 1)
    expect(contrast('#777777', '#ffffff')).toBeCloseTo(4.48, 1)
  })
})
