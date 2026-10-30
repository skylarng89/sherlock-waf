<script setup lang="ts">
import { LineChart } from 'echarts/charts'
import { AriaComponent, GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import Button from 'openvue/button'
import { computed, ref, watch } from 'vue'
import VChart from 'vue-echarts'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import { useApi } from '@/api/useApi'
import { buildOption, buildTable, hasData, timeLabel, type Point } from '@/pages/overview/chart'
import { useReducedMotion } from '@/pages/overview/useReducedMotion'
import { useThemeStore } from '@/stores/theme'

use([LineChart, GridComponent, TooltipComponent, LegendComponent, AriaComponent, CanvasRenderer])

const props = defineProps<{
  from: string
  to: string
  step: '1m' | '5m' | '1h'
  site: string
}>()

const { t, te } = useI18n()
const { client, call } = useApi()
const theme = useThemeStore()
const reducedMotion = useReducedMotion()

const points = ref<Point[]>([])
const bucket = ref('1m')
const state = ref<'loading' | 'ready' | 'error'>('loading')
const asTable = ref(false)
let seq = 0

const actionLabel = (a: string) =>
  te(`overview.chart.actions.${a}`) ? t(`overview.chart.actions.${a}`) : a

async function load() {
  const mine = ++seq
  state.value = 'loading'
  try {
    const res = await call(
      client.GET('/stats/timeseries', {
        params: {
          query: {
            from: props.from,
            to: props.to,
            step: props.step,
            ...(props.site ? { site: props.site } : {}),
          },
        },
      }),
      { toast: false },
    )
    if (mine !== seq) return
    points.value = res.data.points
    bucket.value = res.data.step
    state.value = 'ready'
  } catch (e) {
    if (mine !== seq) return
    if (!isApiError(e)) throw e
    state.value = 'error'
  }
}
watch(() => [props.from, props.to, props.step, props.site], load, { immediate: true })

const option = computed(() =>
  buildOption({
    points: points.value,
    step: bucket.value,
    dark: theme.dark,
    reducedMotion: reducedMotion.value,
    actionLabel,
  }),
)
const table = computed(() => buildTable(points.value))
const populated = computed(() => hasData(points.value))
</script>

<template>
  <section
    aria-labelledby="series-title"
    class="rounded-sk-lg border border-sk-border bg-sk-surface p-4"
    data-testid="series-panel"
  >
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h2 id="series-title" class="text-lg font-medium">{{ t('analytics.series.title') }}</h2>
      <Button
        v-if="state === 'ready' && populated"
        type="button"
        severity="secondary"
        :label="asTable ? t('analytics.viewChart') : t('analytics.viewTable')"
        :aria-pressed="asTable"
        @click="asTable = !asTable"
      />
    </div>
    <p v-if="state === 'loading'" role="status" class="mt-2 text-sk-muted">
      {{ t('analytics.loading') }}…
    </p>
    <p v-else-if="state === 'error'" role="alert" class="mt-2 text-sk-danger">
      {{ t('analytics.loadError') }}
    </p>
    <p v-else-if="!populated" class="mt-2 text-sk-muted">{{ t('analytics.empty') }}</p>
    <div
      v-else-if="asTable"
      class="mt-2 max-h-96 overflow-auto"
      tabindex="0"
      role="region"
      :aria-label="t('analytics.series.tableCaption')"
    >
      <table class="w-full text-left text-sm">
        <caption class="sr-only">
          {{
            t('analytics.series.tableCaption')
          }}
        </caption>
        <thead class="sticky top-0 bg-sk-surface-muted">
          <tr>
            <th scope="col" class="p-2">{{ t('analytics.series.time') }}</th>
            <th v-for="a in table.actions" :key="a" scope="col" class="p-2">
              {{ actionLabel(a) }}
            </th>
            <th scope="col" class="p-2">{{ t('analytics.series.total') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in table.rows" :key="r.t" class="border-t border-sk-border">
            <th scope="row" class="p-2 font-normal">
              <time :datetime="r.t">{{ timeLabel(r.t, bucket) }}</time>
            </th>
            <td v-for="(n, i) in r.counts" :key="table.actions[i]" class="p-2">{{ n }}</td>
            <td class="p-2 font-medium">{{ r.total }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <VChart
      v-else
      class="mt-2 h-80 w-full"
      :option="option"
      autoresize
      role="img"
      :aria-label="t('analytics.series.ariaLabel')"
    />
  </section>
</template>
