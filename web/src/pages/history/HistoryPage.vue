<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import Button from 'openvue/button'
import type { components } from '@/api/schema'
import { isApiError } from '@/api/errors'
import { useApi } from '@/api/useApi'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import ComparePanel from './ComparePanel.vue'
import DiffSummary from './DiffSummary.vue'
import { formatTime } from './format'
import { etagToId, useCurrentVersion } from './useCurrentVersion'

type Version = components['schemas']['Version']

const { t } = useI18n()
const { client, call } = useApi()
const head = useCurrentVersion()

const versions = ref<Version[]>([])
const cursor = ref<string>()
const loading = ref(true)
const loadingMore = ref(false)
const error = ref(false)

const currentId = computed(() => {
  const fromEtag = etagToId(head.etag.value)
  if (fromEtag && versions.value.some((v) => v.id === fromEtag)) return fromEtag
  return versions.value.find((v) => v.applied)?.id
})

async function loadPage(more: boolean) {
  const res = await call(
    client.GET('/config/versions', {
      params: { query: { limit: 50, ...(more && cursor.value ? { cursor: cursor.value } : {}) } },
    }),
    { toast: false },
  )
  versions.value = more ? [...versions.value, ...res.data.items] : res.data.items
  cursor.value = res.data.next_cursor || undefined
}

async function load() {
  loading.value = true
  error.value = false
  try {
    await Promise.all([loadPage(false), head.refresh().catch(() => undefined)])
  } catch (e) {
    if (!isApiError(e)) throw e
    error.value = true
  } finally {
    loading.value = false
  }
}

async function loadMore() {
  loadingMore.value = true
  try {
    await loadPage(true)
  } catch (e) {
    if (!isApiError(e)) throw e
    error.value = true
  } finally {
    loadingMore.value = false
  }
}

onMounted(load)
</script>

<template>
  <SkPageHeader :title="t('history.title')" :description="t('history.description')" />

  <p v-if="loading" role="status" class="text-sk-muted">{{ t('history.loading') }}</p>
  <div
    v-else-if="error && !versions.length"
    role="alert"
    class="flex items-center gap-3 rounded-sk-lg border border-sk-danger bg-sk-danger-bg p-4 text-sk-danger"
  >
    <span>{{ t('history.loadError') }}</span>
    <Button type="button" :label="t('common.actions.retry')" severity="secondary" @click="load" />
  </div>
  <SkEmptyState
    v-else-if="!versions.length"
    icon="ti ti-history"
    :title="t('history.empty.title')"
    :description="t('history.empty.description')"
  />
  <template v-else>
    <p v-if="error" role="alert" class="mb-2 text-sk-danger">{{ t('history.loadError') }}</p>
    <div
      class="overflow-x-auto rounded-sk-lg border border-sk-border bg-sk-surface"
      tabindex="0"
      role="region"
      :aria-label="t('history.listCaption')"
    >
      <table class="w-full text-left text-sm">
        <caption class="sr-only">
          {{
            t('history.listCaption')
          }}
        </caption>
        <thead class="bg-sk-surface-muted">
          <tr>
            <th scope="col" class="p-3">{{ t('history.columns.time') }}</th>
            <th scope="col" class="p-3">{{ t('history.columns.author') }}</th>
            <th scope="col" class="p-3">{{ t('history.columns.source') }}</th>
            <th scope="col" class="p-3">{{ t('history.columns.applied') }}</th>
            <th scope="col" class="p-3">{{ t('history.columns.summary') }}</th>
            <th scope="col" class="p-3">{{ t('history.columns.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="v in versions" :key="v.id" class="border-t border-sk-border">
            <td class="p-3">
              <time :datetime="v.created_at">{{ formatTime(v.created_at) }}</time>
              <span
                v-if="v.id === currentId"
                class="ml-2 inline-flex items-center gap-1 rounded-full bg-sk-success-bg px-2 py-0.5 text-xs font-medium text-sk-success"
                :title="t('history.currentHint')"
              >
                <i class="ti ti-circle-check" aria-hidden="true" />{{ t('history.current') }}
              </span>
            </td>
            <td class="p-3">{{ t('history.author', { type: v.author_type, id: v.author_id }) }}</td>
            <td class="p-3">
              <span class="rounded border border-sk-border-strong px-2 py-0.5 text-xs">
                {{ t(`history.source.${v.source}`) }}
              </span>
            </td>
            <td class="p-3">
              <span class="inline-flex items-center gap-1">
                <i :class="['ti', v.applied ? 'ti-check' : 'ti-x']" aria-hidden="true" />
                {{ v.applied ? t('history.applied') : t('history.notApplied') }}
              </span>
            </td>
            <td class="p-3"><DiffSummary :diff="v.diff" /></td>
            <td class="p-3">
              <RouterLink
                :to="{ name: 'history-detail', params: { id: v.id } }"
                class="text-sk-accent underline"
                :aria-label="t('history.viewVersion', { id: v.id })"
              >
                {{ t('history.view') }}
              </RouterLink>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-if="cursor" class="mt-4">
      <Button
        type="button"
        severity="secondary"
        :label="loadingMore ? t('history.loadingMore') : t('history.loadMore')"
        :disabled="loadingMore"
        @click="loadMore"
      />
    </div>
    <ComparePanel :versions="versions" />
  </template>
</template>
