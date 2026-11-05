<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import Button from 'openvue/button'
import type { components } from '@/api/schema'
import { isApiError } from '@/api/errors'
import { useApi } from '@/api/useApi'
import { compareSites, type CompareRow } from './compare'
import { formatTime } from './format'

type Version = components['schemas']['Version']

defineProps<{ versions: Version[] }>()
const { t } = useI18n()
const { client, call } = useApi()

const left = ref('')
const right = ref('')
const rows = ref<CompareRow[]>()
const error = ref(false)
const busy = ref(false)

async function fetchSites(id: string) {
  const res = await call(client.GET('/config/versions/{id}', { params: { path: { id } } }), {
    toast: false,
  })
  return res.data.snapshot.sites
}

async function compare() {
  if (!left.value || !right.value) return
  busy.value = true
  error.value = false
  try {
    const [a, b] = await Promise.all([fetchSites(left.value), fetchSites(right.value)])
    rows.value = compareSites(a, b, t('history.compare.none'))
  } catch (e) {
    if (!isApiError(e)) throw e
    rows.value = undefined
    error.value = true
  } finally {
    busy.value = false
  }
}

function cell(c?: { hosts: string; mode: string }): string {
  return c ? `${c.hosts} (${c.mode})` : t('history.compare.absent')
}
</script>

<template>
  <section class="mt-8" aria-labelledby="compare-title">
    <h2 id="compare-title" class="text-lg font-medium">{{ t('history.compare.title') }}</h2>
    <p class="text-sk-muted">{{ t('history.compare.description') }}</p>
    <div class="mt-3 flex flex-wrap items-end gap-4">
      <div class="flex flex-col gap-1">
        <label for="cmp-left" class="text-sm font-medium">{{ t('history.compare.left') }}</label>
        <select
          id="cmp-left"
          v-model="left"
          class="rounded-sk border border-sk-border-strong bg-sk-surface p-2"
        >
          <option value="">{{ t('history.compare.choose') }}</option>
          <option v-for="v in versions" :key="v.id" :value="v.id">
            {{ formatTime(v.created_at) }} ({{ v.id }})
          </option>
        </select>
      </div>
      <div class="flex flex-col gap-1">
        <label for="cmp-right" class="text-sm font-medium">{{ t('history.compare.right') }}</label>
        <select
          id="cmp-right"
          v-model="right"
          class="rounded-sk border border-sk-border-strong bg-sk-surface p-2"
        >
          <option value="">{{ t('history.compare.choose') }}</option>
          <option v-for="v in versions" :key="v.id" :value="v.id">
            {{ formatTime(v.created_at) }} ({{ v.id }})
          </option>
        </select>
      </div>
      <Button
        type="button"
        :label="t('history.compare.action')"
        :disabled="!left || !right || busy"
        @click="compare"
      />
    </div>
    <p v-if="error" role="alert" class="mt-3 text-sk-danger">
      {{ t('history.compare.loadError') }}
    </p>
    <div
      v-if="rows"
      class="mt-4 overflow-x-auto rounded-sk-lg border border-sk-border"
      tabindex="0"
      role="region"
      :aria-label="t('history.compare.caption')"
    >
      <table class="w-full text-left text-sm">
        <caption class="sr-only">
          {{
            t('history.compare.caption')
          }}
        </caption>
        <thead class="bg-sk-surface-muted">
          <tr>
            <th scope="col" class="p-3">{{ t('history.compare.site') }}</th>
            <th scope="col" class="p-3">{{ t('history.compare.left') }}</th>
            <th scope="col" class="p-3">{{ t('history.compare.right') }}</th>
            <th scope="col" class="p-3">{{ t('history.compare.same') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in rows" :key="r.site" class="border-t border-sk-border">
            <th scope="row" class="p-3 font-normal">
              <code>{{ r.site }}</code>
            </th>
            <td class="p-3">{{ cell(r.left) }}</td>
            <td class="p-3">{{ cell(r.right) }}</td>
            <td class="p-3">
              <i :class="['ti', r.same ? 'ti-equal' : 'ti-arrows-diff']" aria-hidden="true" />
              {{ r.same ? t('history.compare.same') : t('history.compare.different') }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
