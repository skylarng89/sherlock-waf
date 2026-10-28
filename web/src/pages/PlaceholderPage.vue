<script setup lang="ts">
import { BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import Button from 'openvue/button'
import { computed } from 'vue'
import VChart from 'vue-echarts'
import { useI18n } from 'vue-i18n'
import { useThemeStore } from '@/stores/theme'

use([BarChart, GridComponent, TooltipComponent, CanvasRenderer])

const { t } = useI18n()
const theme = useThemeStore()

const chartOption = computed(() => {
  const text = theme.dark ? '#94a3b8' : '#475569'
  return {
    textStyle: { color: text },
    grid: { left: 32, right: 8, top: 16, bottom: 24 },
    tooltip: {},
    xAxis: { type: 'category', data: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'] },
    yAxis: { type: 'value' },
    series: [{ type: 'bar', data: [12, 18, 9, 22, 15], itemStyle: { color: '#3b82f6' } }],
  }
})
</script>

<template>
  <main class="mx-auto max-w-2xl space-y-6 p-6">
    <header class="flex items-center justify-between">
      <h1 class="flex items-center gap-2 text-2xl font-semibold">
        <i class="ti ti-shield-check text-[var(--sk-accent)]" aria-hidden="true" />
        {{ t('app.name') }}
      </h1>
      <Button
        :label="t('placeholder.darkMode')"
        icon="ti ti-moon"
        severity="secondary"
        :aria-pressed="theme.dark"
        data-testid="theme-toggle"
        @click="theme.toggle()"
      />
    </header>

    <section class="rounded-lg bg-[var(--sk-surface)] p-6 shadow-sm">
      <h2 class="text-lg font-medium">{{ t('placeholder.heading') }}</h2>
      <p class="mt-1 text-[var(--sk-muted)]">{{ t('placeholder.body') }}</p>
      <Button class="mt-4" :label="t('placeholder.action')" icon="ti ti-check" />
    </section>

    <section class="rounded-lg bg-[var(--sk-surface)] p-6 shadow-sm">
      <h2 class="mb-2 text-lg font-medium">{{ t('placeholder.chart') }}</h2>
      <VChart class="h-56" :option="chartOption" autoresize :aria-label="t('placeholder.chart')" />
    </section>
  </main>
</template>
