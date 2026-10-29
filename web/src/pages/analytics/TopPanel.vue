<script setup lang="ts">
import { BarChart } from 'echarts/charts'
import { AriaComponent, GridComponent, TooltipComponent } from 'echarts/components'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import Button from 'openvue/button'
import { computed, ref, watch } from 'vue'
import VChart from 'vue-echarts'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import { useApi } from '@/api/useApi'
import { useReducedMotion } from '@/pages/overview/useReducedMotion'
import { useThemeStore } from '@/stores/theme'
import { buildTopOption, type TopItem } from './topChart'

use([BarChart, GridComponent, TooltipComponent, AriaComponent, CanvasRenderer])

const props = defineProps<{
  dim: 'site' | 'rule' | 'ip' | 'path' | 'country'
  from: string
  to: string
  site: string
}>()

const { t } = useI18n()
const { client, call } = useApi()
const theme = useThemeStore()
const reducedMotion = useReducedMotion()

const items = ref<TopItem[]>([])
const sampled = ref(false)
const state = ref<'loading' | 'ready' | 'error'>('loading')
const asTable = ref(false)
let seq = 0

async function load() {
  const mine = ++seq
  state.value = 'loading'
  try {
    const res = await call(
      client.GET('/stats/top', {
        params: {
          query: {
            dim: props.dim,
            from: props.from,
            to: props.to,
            limit: 10,
            // A site breakdown across sites would collapse to one row when a site is chosen.
            ...(props.site && props.dim !== 'site' ? { site: props.site } : {}),
          },
        },
      }),
      { toast: false },
    )
    if (mine !== seq) return
    items.value = res.data.items
    sampled.value = res.data.sampled
    state.value = 'ready'
  } catch (e) {
    if (mine !== seq) return
    if (!isApiError(e)) throw e
    state.value = 'error'
  }
}
watch(() => [props.dim, props.from, props.to, props.site], load, { immediate: true })

const option = computed(() =>
  buildTopOption({ items: items.value, dark: theme.dark, reducedMotion: reducedMotion.value }),
)
const headingId = computed(() => `top-${props.dim}`)
</script>

<template>
  <section
    :aria-labelledby="headingId"
    class="rounded-sk-lg border border-sk-border bg-sk-surface p-4"
    :data-testid="`top-${dim}`"
  >
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h2 :id="headingId" class="text-lg font-medium">{{ t(`analytics.top.${dim}.title`) }}</h2>
      <Button
        v-if="state === 'ready' && items.length"
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
    <p v-else-if="!items.length" class="mt-2 text-sk-muted">{{ t('analytics.empty') }}</p>
    <template v-else>
      <p v-if="sampled" class="mt-2 text-sm text-sk-muted">
        <i class="ti ti-info-circle" aria-hidden="true" /> {{ t('analytics.sampled') }}
      </p>
      <div
        v-if="asTable"
        class="mt-2 max-h-80 overflow-auto"
        tabindex="0"
        role="region"
        :aria-label="t(`analytics.top.${dim}.title`)"
      >
        <table class="w-full text-left text-sm">
          <caption class="sr-only">
            {{
              t('analytics.top.tableCaption')
            }}
          </caption>
          <thead>
            <tr>
              <th scope="col" class="p-2">{{ t('analytics.top.rank') }}</th>
              <th scope="col" class="p-2">{{ t(`analytics.top.${dim}.value`) }}</th>
              <th scope="col" class="p-2">{{ t('analytics.top.count') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(i, n) in items" :key="i.value" class="border-t border-sk-border">
              <td class="p-2">{{ n + 1 }}</td>
              <th scope="row" class="break-all p-2 font-mono font-normal">{{ i.value }}</th>
              <td class="p-2">{{ i.count }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <VChart
        v-else
        class="mt-2 w-full"
        :style="{ height: `${Math.max(items.length * 32 + 24, 120)}px` }"
        :option="option"
        autoresize
        role="img"
        :aria-label="t('analytics.top.chartLabel', { n: items.length })"
      />
    </template>
  </section>
</template>
