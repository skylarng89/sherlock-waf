import type { EChartsCoreOption } from 'echarts/core'

export interface TopItem {
  value: string
  count: number
}

/** Horizontal bars, largest first. One series, so colour carries no meaning beyond "count". */
export function buildTopOption(input: {
  items: TopItem[]
  dark: boolean
  reducedMotion: boolean
}): EChartsCoreOption {
  const { items, dark } = input
  const text = dark ? '#e2e8f0' : '#0f172a'
  const muted = dark ? '#a3b2c7' : '#475569'
  const grid = dark ? '#26324b' : '#e2e8f0'
  const color = dark ? '#56b4e9' : '#0072b2'
  const ordered = [...items].reverse()
  return {
    animation: !input.reducedMotion,
    textStyle: { color: text },
    aria: { enabled: true },
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, confine: true },
    grid: { left: 16, right: 32, top: 8, bottom: 8, containLabel: true },
    xAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: muted },
      splitLine: { lineStyle: { color: grid } },
    },
    yAxis: {
      type: 'category',
      data: ordered.map((i) => i.value),
      axisLabel: { color: muted, width: 160, overflow: 'truncate' },
      axisLine: { lineStyle: { color: muted } },
    },
    series: [
      {
        type: 'bar',
        data: ordered.map((i) => i.count),
        itemStyle: { color },
        label: { show: true, position: 'right', color: text },
      },
    ],
  }
}
