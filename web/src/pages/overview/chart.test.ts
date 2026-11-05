import { describe, expect, it } from 'vitest'
import {
  buildOption,
  buildTable,
  hasData,
  presentActions,
  rangeQuery,
  RANGES,
  type Point,
} from './chart'

const points: Point[] = [
  { t: '2026-10-01T10:00:00Z', counts: { allow: 5, block: 2, weird: 1 } },
  { t: '2026-10-01T10:01:00Z', counts: { allow: 3, ban: 1 } },
]
const input = {
  points,
  step: '1m',
  dark: false,
  reducedMotion: false,
  actionLabel: (a: string) => a.toUpperCase(),
}

describe('chart helpers', () => {
  it('orders known actions first and keeps unknown ones', () => {
    expect(presentActions(points)).toEqual(['allow', 'block', 'ban', 'weird'])
  })

  it('detects empty data', () => {
    expect(hasData([])).toBe(false)
    expect(hasData([{ t: 'x', counts: { allow: 0 } }])).toBe(false)
    expect(hasData(points)).toBe(true)
  })

  it('builds one series per present action with distinct line styles and symbols', () => {
    const o = buildOption(input) as {
      series: { name: string; data: number[]; lineStyle: { type: unknown }; symbol: string }[]
    }
    expect(o.series.map((s) => s.name)).toEqual(['ALLOW', 'BLOCK', 'BAN', 'WEIRD'])
    expect(o.series[0]?.data).toEqual([5, 3])
    expect(o.series[1]?.data).toEqual([2, 0])
    const known = o.series.slice(0, 3)
    expect(new Set(known.map((s) => JSON.stringify(s.lineStyle.type) + s.symbol)).size).toBe(3)
  })

  it('uses different colours in dark mode and disables animation for reduced motion', () => {
    const light = buildOption(input) as { series: { color: string }[]; animation: boolean }
    const dark = buildOption({ ...input, dark: true, reducedMotion: true }) as typeof light
    expect(light.series[0]?.color).not.toBe(dark.series[0]?.color)
    expect(light.animation).toBe(true)
    expect(dark.animation).toBe(false)
  })

  it('table carries the same numbers as the series', () => {
    const t = buildTable(points)
    expect(t.actions).toEqual(['allow', 'block', 'ban', 'weird'])
    expect(t.rows[0]).toEqual({ t: points[0]?.t, counts: [5, 2, 0, 1], total: 8 })
  })

  it('computes from/to/step within the server cap', () => {
    const now = new Date('2026-10-01T10:00:30Z')
    expect(rangeQuery('1h', now)).toEqual({
      from: '2026-10-01T09:00:00.000Z',
      to: '2026-10-01T10:00:00.000Z',
      step: '1m',
    })
    for (const r of Object.values(RANGES)) {
      const unit = r.step === '1m' ? 60_000 : r.step === '5m' ? 300_000 : 3_600_000
      expect(r.ms / unit).toBeLessThanOrEqual(2000)
    }
  })
})
