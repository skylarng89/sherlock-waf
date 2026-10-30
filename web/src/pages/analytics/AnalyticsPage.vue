<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useApi } from '@/api/useApi'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { RANGE_KEYS, rangeQuery, type RangeKey } from '@/pages/overview/chart'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import SeriesPanel from './SeriesPanel.vue'
import TopPanel from './TopPanel.vue'

const { t } = useI18n()
const { client, call } = useApi()

const range = ref<RangeKey>('24h')
const site = ref('')
const sites = ref<string[]>([])
// Recomputed only when the range changes, so the panels fetch once per change.
const bounds = computed(() => rangeQuery(range.value, new Date()))

onMounted(async () => {
  try {
    sites.value = (await call(client.GET('/sites'), { toast: false })).data.items.map((s) => s.id)
  } catch {
    sites.value = []
  }
})

const DIMS = ['site', 'rule', 'ip', 'path', 'country'] as const
</script>

<template>
  <SkPageHeader :title="t('analytics.title')" :description="t('analytics.description')" />

  <div class="mb-6 flex flex-wrap gap-4">
    <SkFormField :label="t('analytics.range')">
      <template #default="{ attrs }">
        <SelectControl
          v-bind="attrs"
          :model-value="range"
          :options="RANGE_KEYS.map((k) => ({ value: k, label: t(`analytics.ranges.${k}`) }))"
          @update:model-value="range = $event ?? '24h'"
        />
      </template>
    </SkFormField>
    <SkFormField :label="t('analytics.site')">
      <template #default="{ attrs }">
        <SelectControl
          v-bind="attrs"
          :model-value="site || undefined"
          :options="sites.map((s) => ({ value: s, label: s }))"
          :empty-label="t('analytics.allSites')"
          @update:model-value="site = $event ?? ''"
        />
      </template>
    </SkFormField>
  </div>

  <div class="flex flex-col gap-6">
    <SeriesPanel :from="bounds.from" :to="bounds.to" :step="bounds.step" :site="site" />
    <div class="grid gap-6 lg:grid-cols-2">
      <TopPanel
        v-for="dim in DIMS"
        :key="dim"
        :dim="dim"
        :from="bounds.from"
        :to="bounds.to"
        :site="site"
      />
    </div>
  </div>
</template>
