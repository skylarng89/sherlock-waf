<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { CRS_STATE_ICON } from './lib'

type RuleList = components['schemas']['CrsRuleList']

const PAGE = 50
const { t } = useI18n()
const { client, call } = useApi()

const filters = reactive({
  q: '',
  site: '',
  category: '',
  paranoia: '',
  direction: '',
  state: '',
})
const sites = ref<string[]>([])
const list = ref<RuleList>()
const offset = ref(0)
const state = ref<'loading' | 'ready' | 'error'>('loading')

const from = computed(() => (list.value && list.value.total ? offset.value + 1 : 0))
const to = computed(() => Math.min(offset.value + PAGE, list.value?.total ?? 0))

async function load() {
  state.value = 'loading'
  try {
    const res = await call(
      client.GET('/crs/rules', {
        params: {
          query: {
            ...(filters.q ? { q: filters.q } : {}),
            ...(filters.site ? { site: filters.site } : {}),
            ...(filters.category ? { category: filters.category } : {}),
            ...(filters.paranoia ? { paranoia_level: Number(filters.paranoia) } : {}),
            ...(filters.direction
              ? { direction: filters.direction as 'request' | 'response' }
              : {}),
            ...(filters.state && filters.site
              ? { state: filters.state as components['schemas']['CrsRuleStatus']['state'] }
              : {}),
            limit: PAGE,
            offset: offset.value,
          },
        },
      }),
      { toast: false },
    )
    list.value = res.data
    state.value = 'ready'
  } catch (e) {
    if (!isApiError(e)) throw e
    state.value = 'error'
  }
}

function apply() {
  offset.value = 0
  void load()
}
function reset() {
  Object.assign(filters, { q: '', site: '', category: '', paranoia: '', direction: '', state: '' })
  apply()
}
function page(delta: number) {
  offset.value = Math.max(0, offset.value + delta * PAGE)
  void load()
}

onMounted(async () => {
  try {
    const res = await call(client.GET('/sites'), { toast: false })
    sites.value = res.data.items.map((s) => s.id)
  } catch (e) {
    if (!isApiError(e)) throw e
  }
  await load()
})

const field = 'rounded-sk border border-sk-border-strong bg-sk-surface px-3 py-2'
</script>

<template>
  <SkPageHeader :title="t('tuning.crs.title')" :description="t('tuning.crs.description')" />

  <form class="mb-4 flex flex-wrap items-end gap-3" role="search" @submit.prevent="apply">
    <div class="flex flex-col gap-1">
      <label for="crs-q" class="text-sm font-medium">{{ t('tuning.crs.search') }}</label>
      <input id="crs-q" v-model="filters.q" type="search" :class="field" autocomplete="off" />
    </div>
    <div class="flex flex-col gap-1">
      <label for="crs-site" class="text-sm font-medium">{{ t('tuning.crs.site') }}</label>
      <select id="crs-site" v-model="filters.site" :class="field">
        <option value="">{{ t('tuning.crs.noSite') }}</option>
        <option v-for="s in sites" :key="s" :value="s">{{ s }}</option>
      </select>
    </div>
    <div class="flex flex-col gap-1">
      <label for="crs-cat" class="text-sm font-medium">{{ t('tuning.crs.category') }}</label>
      <select id="crs-cat" v-model="filters.category" :class="field">
        <option value="">{{ t('tuning.crs.anyCategory') }}</option>
        <option v-for="c in list?.categories ?? []" :key="c" :value="c">{{ c }}</option>
      </select>
    </div>
    <div class="flex flex-col gap-1">
      <label for="crs-pl" class="text-sm font-medium">{{ t('tuning.crs.paranoia') }}</label>
      <select id="crs-pl" v-model="filters.paranoia" :class="field">
        <option value="">{{ t('tuning.crs.anyParanoia') }}</option>
        <option v-for="n in 4" :key="n" :value="String(n)">{{ n }}</option>
      </select>
    </div>
    <div class="flex flex-col gap-1">
      <label for="crs-dir" class="text-sm font-medium">{{ t('tuning.crs.direction') }}</label>
      <select id="crs-dir" v-model="filters.direction" :class="field">
        <option value="">{{ t('tuning.crs.anyDirection') }}</option>
        <option value="request">{{ t('tuning.crs.request') }}</option>
        <option value="response">{{ t('tuning.crs.response') }}</option>
      </select>
    </div>
    <div v-if="filters.site" class="flex flex-col gap-1">
      <label for="crs-state" class="text-sm font-medium">{{ t('tuning.crs.state') }}</label>
      <select id="crs-state" v-model="filters.state" :class="field">
        <option value="">{{ t('tuning.crs.anyState') }}</option>
        <option v-for="s in Object.keys(CRS_STATE_ICON)" :key="s" :value="s">
          {{ t(`tuning.crs.states.${s}`) }}
        </option>
      </select>
    </div>
    <Button type="submit" :label="t('tuning.crs.apply')" />
    <Button type="button" :label="t('tuning.crs.reset')" severity="secondary" @click="reset" />
  </form>

  <div role="status" aria-live="polite">
    <p v-if="state === 'loading'">{{ t('tuning.crs.loading') }}…</p>
    <p v-else-if="list" class="mb-2 text-sk-muted" data-testid="crs-total">
      {{ t('tuning.crs.version', { version: list.crs_version }) }} ·
      {{ t('tuning.crs.total', { total: list.total }) }}
    </p>
  </div>
  <div v-if="state === 'error'" role="alert" class="text-sk-danger">
    {{ t('tuning.crs.loadFailed') }}
    <Button :label="t('common.actions.retry')" severity="secondary" @click="load" />
  </div>

  <template v-else-if="list">
    <SkEmptyState v-if="!list.items.length" :title="t('tuning.crs.empty')" icon="ti ti-search" />
    <div
      v-else
      class="overflow-x-auto"
      tabindex="0"
      role="region"
      :aria-label="t('tuning.crs.scroll')"
    >
      <table class="w-full text-left text-sm" data-testid="crs-table">
        <caption class="sr-only">
          {{
            t('tuning.crs.caption')
          }}
        </caption>
        <thead>
          <tr class="border-b border-sk-border-strong">
            <th scope="col" class="p-2">{{ t('tuning.crs.cols.id') }}</th>
            <th scope="col" class="p-2">{{ t('tuning.crs.cols.message') }}</th>
            <th scope="col" class="p-2">{{ t('tuning.crs.cols.category') }}</th>
            <th scope="col" class="p-2">{{ t('tuning.crs.cols.pl') }}</th>
            <th scope="col" class="p-2">{{ t('tuning.crs.cols.severity') }}</th>
            <th scope="col" class="p-2">{{ t('tuning.crs.cols.direction') }}</th>
            <th v-if="filters.site" scope="col" class="p-2">{{ t('tuning.crs.cols.state') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in list.items" :key="r.id" class="border-b border-sk-border align-top">
            <th scope="row" class="p-2 font-mono font-normal">{{ r.id }}</th>
            <td class="p-2">{{ r.message }}</td>
            <td class="p-2">{{ r.category }}</td>
            <td class="p-2">{{ r.paranoia_level }}</td>
            <td class="p-2">{{ r.severity ?? '–' }}</td>
            <td class="p-2">{{ t(`tuning.crs.${r.direction}`) }}</td>
            <td v-if="filters.site" class="p-2">
              <template v-if="r.status">
                <span class="whitespace-nowrap font-medium" data-testid="crs-state">
                  <i :class="CRS_STATE_ICON[r.status.state]" aria-hidden="true" />
                  {{ t(`tuning.crs.states.${r.status.state}`) }}
                </span>
                <span v-if="r.status.reason" class="block text-sk-muted">
                  {{ t(`tuning.crs.reasons.${r.status.reason}`) }}
                </span>
                <span v-if="r.status.excluded_by?.length" class="block font-mono text-sk-muted">
                  {{ t('tuning.crs.excludedBy', { ids: r.status.excluded_by.join(', ') }) }}
                </span>
              </template>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <nav
      v-if="list.total > PAGE"
      class="mt-3 flex items-center gap-3"
      :aria-label="t('tuning.crs.caption')"
    >
      <Button
        :label="t('tuning.crs.prev')"
        severity="secondary"
        :disabled="offset === 0"
        @click="page(-1)"
      />
      <span>{{ t('tuning.crs.shown', { from, to }) }}</span>
      <Button
        :label="t('tuning.crs.next')"
        severity="secondary"
        :disabled="offset + PAGE >= list.total"
        @click="page(1)"
      />
    </nav>
  </template>
</template>
