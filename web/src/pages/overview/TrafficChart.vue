<script setup lang="ts">
import { LineChart } from 'echarts/charts'
import { AriaComponent, GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import Button from 'openvue/button'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import VChart from 'vue-echarts'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import { useApi } from '@/api/useApi'
import SkEmptyState from '@/components/SkEmptyState.vue'
import { useThemeStore } from '@/stores/theme'
import {
  buildOption,
  buildTable,
  hasData,
  RANGE_KEYS,
  rangeQuery,
  timeLabel,
  type Point,
  type RangeKey,
} from './chart'
import { useReducedMotion } from './useReducedMotion'

use([LineChart, GridComponent, TooltipComponent, LegendComponent, AriaComponent, CanvasRenderer])

const REFRESH_MS = 30_000

defineProps<{ sites: string[] }>()

const { t, te } = useI18n()
const { client, call } = useApi()
const theme = useThemeStore()
const reducedMotion = useReducedMotion()

const range = ref<RangeKey>('1h')
const site = ref('')
const paused = ref(false)
const asTable = ref(false)
const points = ref<Point[]>([])
const step = ref('1m')
const loading = ref(true)
const error = ref(false)
const updated = ref<Date>()
let timer: ReturnType<typeof setInterval> | undefined
let requestSeq = 0

function actionLabel(a: string): string {
  return te(`overview.chart.actions.${a}`) ? t(`overview.chart.actions.${a}`) : a
}

const option = computed(() =>
  buildOption({
    points: points.value,
    step: step.value,
    dark: theme.dark,
    reducedMotion: reducedMotion.value,
    actionLabel,
  }),
)
const table = computed(() => buildTable(points.value))
const populated = computed(() => hasData(points.value))

async function load() {
  const seq = ++requestSeq
  const q = rangeQuery(range.value, new Date())
  try {
    const res = await call(
      client.GET('/stats/timeseries', {
        params: { query: { ...q, ...(site.value ? { site: site.value } : {}) } },
      }),
      { toast: false },
    )
    if (seq !== requestSeq) return
    points.value = res.data.points
    step.value = res.data.step
    updated.value = new Date()
    error.value = false
  } catch (e) {
    if (seq !== requestSeq) return
    if (!isApiError(e)) throw e
    error.value = true
  } finally {
    if (seq === requestSeq) loading.value = false
  }
}

function startTimer() {
  stopTimer()
  if (!paused.value) timer = setInterval(() => void load(), REFRESH_MS)
}
function stopTimer() {
  if (timer) clearInterval(timer)
  timer = undefined
}

function togglePause() {
  paused.value = !paused.value
  startTimer()
  if (!paused.value) void load()
}

watch([range, site], () => {
  loading.value = true
  void load()
  startTimer()
})
onMounted(() => {
  void load()
  startTimer()
})
onBeforeUnmount(stopTimer)
</script>

<template>
  <section
    aria-labelledby="traffic-title"
    class="rounded-sk-lg border border-sk-border bg-sk-surface p-4"
  >
    <div class="flex flex-wrap items-end justify-between gap-4">
      <h2 id="traffic-title" class="text-lg font-medium">{{ t('overview.chart.title') }}</h2>
      <div class="flex flex-wrap items-end gap-4">
        <div class="flex flex-col gap-1">
          <label for="ov-range" class="text-sm font-medium">{{ t('overview.chart.range') }}</label>
          <select
            id="ov-range"
            v-model="range"
            class="rounded-sk border border-sk-border-strong bg-sk-surface p-2"
          >
            <option v-for="k in RANGE_KEYS" :key="k" :value="k">
              {{ t(`overview.chart.ranges.${k}`) }}
            </option>
          </select>
        </div>
        <div v-if="sites.length" class="flex flex-col gap-1">
          <label for="ov-site" class="text-sm font-medium">{{ t('overview.chart.site') }}</label>
          <select
            id="ov-site"
            v-model="site"
            class="rounded-sk border border-sk-border-strong bg-sk-surface p-2"
          >
            <option value="">{{ t('overview.chart.allSites') }}</option>
            <option v-for="s in sites" :key="s" :value="s">{{ s }}</option>
          </select>
        </div>
        <Button
          type="button"
          severity="secondary"
          :label="paused ? t('overview.chart.resume') : t('overview.chart.pause')"
          :aria-pressed="paused"
          @click="togglePause"
        />
        <Button
          v-if="populated"
          type="button"
          severity="secondary"
          :label="asTable ? t('overview.chart.viewChart') : t('overview.chart.viewTable')"
          :aria-pressed="asTable"
          @click="asTable = !asTable"
        />
      </div>
    </div>
    <p role="status" class="mt-2 text-sm text-sk-muted">
      {{ paused ? t('overview.chart.paused') : t('overview.chart.refreshing') }}
      <template v-if="updated">
        &middot; {{ t('overview.chart.updated', { time: updated.toLocaleTimeString() }) }}
      </template>
    </p>

    <p v-if="loading" role="status" class="mt-4 text-sk-muted">{{ t('overview.chart.loading') }}</p>
    <p v-else-if="error && !points.length" role="alert" class="mt-4 text-sk-danger">
      {{ t('overview.chart.loadError') }}
    </p>
    <template v-else>
      <p v-if="error" role="alert" class="mt-4 text-sk-danger">
        {{ t('overview.chart.loadError') }}
      </p>
      <SkEmptyState
        v-if="!populated"
        class="mt-4"
        icon="ti ti-chart-line"
        :title="t('overview.chart.emptyTitle')"
        :description="t('overview.chart.emptyDescription')"
      />
      <div
        v-else-if="asTable"
        class="mt-4 max-h-96 overflow-auto"
        tabindex="0"
        role="region"
        :aria-label="t('overview.chart.tableCaption')"
      >
        <table class="w-full text-left text-sm">
          <caption class="sr-only">
            {{
              t('overview.chart.tableCaption')
            }}
          </caption>
          <thead class="sticky top-0 bg-sk-surface-muted">
            <tr>
              <th scope="col" class="p-2">{{ t('overview.chart.time') }}</th>
              <th v-for="a in table.actions" :key="a" scope="col" class="p-2">
                {{ actionLabel(a) }}
              </th>
              <th scope="col" class="p-2">{{ t('overview.chart.total') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in table.rows" :key="r.t" class="border-t border-sk-border">
              <th scope="row" class="p-2 font-normal">
                <time :datetime="r.t">{{ timeLabel(r.t, step) }}</time>
              </th>
              <td v-for="(n, i) in r.counts" :key="table.actions[i]" class="p-2">{{ n }}</td>
              <td class="p-2 font-medium">{{ r.total }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <VChart
        v-else
        class="mt-4 h-80 w-full"
        :option="option"
        autoresize
        role="img"
        :aria-label="t('overview.chart.ariaLabel')"
      />
    </template>
  </section>
</template>
