import type { EChartsCoreOption } from 'echarts/core'

export type RangeKey = '1h' | '6h' | '24h' | '7d'
export type Step = '1m' | '5m' | '1h'

// Every step keeps the bucket count far below the server cap of 2000 (7d at 1h is 168).
export const RANGES: Record<RangeKey, { ms: number; step: Step }> = {
  '1h': { ms: 3_600_000, step: '1m' },
  '6h': { ms: 6 * 3_600_000, step: '5m' },
  '24h': { ms: 24 * 3_600_000, step: '5m' },
  '7d': { ms: 7 * 24 * 3_600_000, step: '1h' },
}
export const RANGE_KEYS = Object.keys(RANGES) as RangeKey[]

/** The query for a range, anchored to the minute so repeated refreshes share a key. */
export function rangeQuery(range: RangeKey, now: Date) {
  const to = new Date(Math.floor(now.getTime() / 60_000) * 60_000)
  const from = new Date(to.getTime() - RANGES[range].ms)
  return { from: from.toISOString(), to: to.toISOString(), step: RANGES[range].step }
}

export const ACTIONS = ['allow', 'log', 'challenge', 'block', 'ratelimit', 'ban'] as const
export type ActionName = (typeof ACTIONS)[number]

type Dash = 'solid' | 'dashed' | 'dotted' | number[]

// Colour is never the only channel: each action also has its own line pattern and marker shape.
// Palette is Okabe-Ito based (colour-blind safe); light values keep 3:1 on white, dark on #111a2e.
export const ACTION_STYLE: Record<
  ActionName,
  { light: string; dark: string; dash: Dash; symbol: string }
> = {
  allow: { light: '#0072b2', dark: '#56b4e9', dash: 'solid', symbol: 'circle' },
  log: { light: '#007a5a', dark: '#2bc299', dash: 'dashed', symbol: 'rect' },
  challenge: { light: '#9a6700', dark: '#f0b429', dash: 'dotted', symbol: 'triangle' },
  block: { light: '#c2410c', dark: '#ff8a4c', dash: 'solid', symbol: 'diamond' },
  ratelimit: { light: '#a8447f', dark: '#e58fc1', dash: [10, 3, 2, 3], symbol: 'arrow' },
  ban: { light: '#111827', dark: '#e5e7eb', dash: [2, 2], symbol: 'pin' },
}
const FALLBACK = { light: '#475569', dark: '#a3b2c7', dash: 'dashed' as Dash, symbol: 'circle' }

export interface Point {
  t: string
  counts: Record<string, number>
}

/** Known actions first, in a fixed order, then any action the server added later. */
export function presentActions(points: Point[]): string[] {
  const seen = new Set(points.flatMap((p) => Object.keys(p.counts)))
  const known = ACTIONS.filter((a) => seen.has(a))
  const extra = [...seen].filter((a) => !(ACTIONS as readonly string[]).includes(a)).sort()
  return [...known, ...extra]
}

export function hasData(points: Point[]): boolean {
  return points.some((p) => Object.values(p.counts).some((n) => n > 0))
}

function styleFor(action: string) {
  return action in ACTION_STYLE ? ACTION_STYLE[action as ActionName] : FALLBACK
}

export function timeLabel(iso: string, step: string, locale?: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return step === '1h' || step === '1d'
    ? d.toLocaleString(locale, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      })
    : d.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' })
}

export interface ChartInput {
  points: Point[]
  step: string
  dark: boolean
  reducedMotion: boolean
  actionLabel: (action: string) => string
}

export function buildOption(input: ChartInput): EChartsCoreOption {
  const { points, dark } = input
  const actions = presentActions(points)
  const text = dark ? '#e2e8f0' : '#0f172a'
  const muted = dark ? '#a3b2c7' : '#475569'
  const grid = dark ? '#26324b' : '#e2e8f0'
  const showSymbol = points.length <= 80
  return {
    animation: !input.reducedMotion,
    textStyle: { color: text },
    aria: { enabled: true },
    legend: {
      data: actions.map(input.actionLabel),
      textStyle: { color: text },
      icon: 'path://M0,4 L14,4 L14,6 L0,6 Z',
    },
    tooltip: { trigger: 'axis', confine: true },
    grid: { left: 48, right: 16, top: 48, bottom: 32, containLabel: true },
    xAxis: {
      type: 'category',
      data: points.map((p) => timeLabel(p.t, input.step)),
      axisLine: { lineStyle: { color: muted } },
      axisLabel: { color: muted },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: muted },
      splitLine: { lineStyle: { color: grid } },
    },
    series: actions.map((a) => {
      const s = styleFor(a)
      const color = dark ? s.dark : s.light
      return {
        name: input.actionLabel(a),
        type: 'line',
        data: points.map((p) => p.counts[a] ?? 0),
        color,
        itemStyle: { color },
        lineStyle: { color, type: s.dash, width: 2 },
        symbol: s.symbol,
        symbolSize: 7,
        showSymbol,
      }
    }),
  }
}

export interface TableModel {
  actions: string[]
  rows: { t: string; counts: number[]; total: number }[]
}

/** The same numbers the chart plots, for the table alternative. */
export function buildTable(points: Point[]): TableModel {
  const actions = presentActions(points)
  return {
    actions,
    rows: points.map((p) => {
      const counts = actions.map((a) => p.counts[a] ?? 0)
      return { t: p.t, counts, total: counts.reduce((x, y) => x + y, 0) }
    }),
  }
}
