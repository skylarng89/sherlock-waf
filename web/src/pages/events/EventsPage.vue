<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { isApiError } from '@/api/errors'
import { useApi } from '@/api/useApi'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { formatTime } from '@/pages/history/format'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import ActionBadge from './ActionBadge.vue'
import { toView, ruleIds, type EventView } from './event'
import {
  ACTIONS,
  apiQuery,
  emptyFilters,
  fromLocalInput,
  parseFilters,
  RANGE_KEYS,
  toLocalInput,
  toQuery,
  type Filters,
} from './filters'

const POLL_MS = 5_000
const PAGE_SIZE = 50

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const { client, call } = useApi()

const filters = computed(() => parseFilters(route.query))
const draft = reactive<Filters>(emptyFilters())

const rows = ref<EventView[]>([])
const nextCursor = ref<string>()
// Cursors of the pages already visited; the last one is the page on screen.
const cursors = ref<(string | undefined)[]>([undefined])
const state = ref<'loading' | 'ready' | 'error'>('loading')
const refreshError = ref(false)
const paused = ref(false)
const sites = ref<string[]>([])
const announcement = ref('')
let timer: ReturnType<typeof setInterval> | undefined
let seq = 0

const onFirstPage = computed(() => cursors.value.length === 1)
const live = computed(() => !paused.value && onFirstPage.value)

async function load(silent = false) {
  const mine = ++seq
  if (!silent) state.value = 'loading'
  try {
    const res = await call(
      client.GET('/events', {
        params: {
          query: {
            ...apiQuery(filters.value, new Date()),
            limit: PAGE_SIZE,
            ...(cursors.value[cursors.value.length - 1]
              ? { cursor: cursors.value[cursors.value.length - 1] }
              : {}),
          },
        },
      }),
      { toast: false },
    )
    if (mine !== seq) return
    rows.value = res.data.items.map(toView)
    nextCursor.value = res.data.next_cursor
    state.value = 'ready'
    refreshError.value = false
    // Silent polls stay quiet for screen readers; only a user-initiated load is announced.
    if (!silent) announcement.value = t('events.summary', { count: rows.value.length })
  } catch (e) {
    if (mine !== seq) return
    if (!isApiError(e)) throw e
    if (silent && state.value === 'ready') refreshError.value = true
    else state.value = 'error'
  }
}

function stopTimer() {
  if (timer !== undefined) clearInterval(timer)
  timer = undefined
}
function syncTimer() {
  stopTimer()
  if (live.value) timer = setInterval(() => void load(true), POLL_MS)
}

function togglePause() {
  paused.value = !paused.value
  syncTimer()
  if (!paused.value && onFirstPage.value) void load(true)
}

function syncDraft() {
  Object.assign(draft, filters.value)
}

function apply() {
  const next = { ...draft }
  next.country = next.country.trim().toUpperCase()
  void router.push({ query: toQuery(next) })
}
function reset() {
  void router.push({ query: {} })
}

watch(
  () => route.query,
  () => {
    syncDraft()
    cursors.value = [undefined]
    syncTimer()
    void load()
  },
)

function older() {
  if (!nextCursor.value) return
  cursors.value = [...cursors.value, nextCursor.value]
  syncTimer()
  void load()
}
function newer() {
  if (cursors.value.length < 2) return
  cursors.value = cursors.value.slice(0, -1)
  syncTimer()
  void load()
}

async function loadSites() {
  try {
    sites.value = (await call(client.GET('/sites'), { toast: false })).data.items.map((s) => s.id)
  } catch {
    sites.value = []
  }
}

onMounted(() => {
  syncDraft()
  void load()
  void loadSites()
  syncTimer()
})
onBeforeUnmount(stopTimer)

const siteOptions = computed(() => {
  const ids = new Set(sites.value)
  if (draft.site) ids.add(draft.site)
  return [...ids].map((id) => ({ value: id, label: id }))
})
const actionOptions = ACTIONS.map((a) => ({ value: a, label: a }))
const rangeOptions = RANGE_KEYS.map((k) => ({ value: k, label: k }))
const localFrom = computed({
  get: () => toLocalInput(draft.from),
  set: (v: string) => (draft.from = fromLocalInput(v)),
})
const localTo = computed({
  get: () => toLocalInput(draft.to),
  set: (v: string) => (draft.to = fromLocalInput(v)),
})
const dateClass =
  'w-full rounded-sk border border-sk-border-strong bg-sk-surface px-3 py-2 text-sk-text'

const rulesOf = (e: EventView) => ruleIds(e)
const requestLabel = (e: EventView) => `${e.request.method} ${e.request.path}`
</script>

<template>
  <SkPageHeader :title="t('events.title')" :description="t('events.description')">
    <template #actions>
      <Button
        type="button"
        severity="secondary"
        :icon="paused ? 'ti ti-player-play' : 'ti ti-player-pause'"
        :label="paused ? t('events.live.resume') : t('events.live.pause')"
        :aria-pressed="paused"
        @click="togglePause"
      />
    </template>
  </SkPageHeader>

  <form
    class="mb-6 rounded-sk-lg border border-sk-border bg-sk-surface p-4"
    novalidate
    role="search"
    :aria-label="t('events.filters.title')"
    @submit.prevent="apply"
  >
    <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <SkFormField :label="t('events.filters.site')">
        <template #default="{ attrs }">
          <SelectControl
            v-bind="attrs"
            :model-value="draft.site"
            :options="siteOptions"
            :empty-label="t('events.filters.allSites')"
            @update:model-value="draft.site = $event ?? ''"
          />
        </template>
      </SkFormField>
      <SkFormField :label="t('events.filters.action')">
        <template #default="{ attrs }">
          <SelectControl
            v-bind="attrs"
            :model-value="draft.action || undefined"
            :options="actionOptions.map((o) => ({ ...o, label: t(`events.actions.${o.value}`) }))"
            :empty-label="t('events.filters.anyAction')"
            @update:model-value="draft.action = $event ?? ''"
          />
        </template>
      </SkFormField>
      <SkFormField :label="t('events.filters.rule')">
        <template #default="{ attrs }">
          <TextControl v-bind="attrs" v-model="draft.rule_id" mono />
        </template>
      </SkFormField>
      <SkFormField :label="t('events.filters.ip')">
        <template #default="{ attrs }">
          <TextControl v-bind="attrs" v-model="draft.ip" mono />
        </template>
      </SkFormField>
      <SkFormField :label="t('events.filters.country')" :help="t('events.filters.countryHelp')">
        <template #default="{ attrs }">
          <TextControl v-bind="attrs" v-model="draft.country" mono maxlength="2" />
        </template>
      </SkFormField>
      <SkFormField :label="t('events.filters.method')">
        <template #default="{ attrs }">
          <TextControl v-bind="attrs" v-model="draft.method" mono />
        </template>
      </SkFormField>
      <SkFormField :label="t('events.filters.status')">
        <template #default="{ attrs }">
          <TextControl v-bind="attrs" v-model="draft.status" mono inputmode="numeric" />
        </template>
      </SkFormField>
      <SkFormField :label="t('events.filters.q')" :help="t('events.filters.qHelp')">
        <template #default="{ attrs }">
          <TextControl v-bind="attrs" v-model="draft.q" />
        </template>
      </SkFormField>
      <SkFormField :label="t('events.filters.range')">
        <template #default="{ attrs }">
          <SelectControl
            v-bind="attrs"
            :model-value="draft.range"
            :options="
              rangeOptions.map((o) => ({ ...o, label: t(`events.filters.ranges.${o.value}`) }))
            "
            @update:model-value="draft.range = $event ?? '24h'"
          />
        </template>
      </SkFormField>
      <template v-if="draft.range === 'custom'">
        <SkFormField :label="t('events.filters.from')">
          <template #default="{ attrs }">
            <input v-bind="attrs" v-model="localFrom" type="datetime-local" :class="dateClass" />
          </template>
        </SkFormField>
        <SkFormField :label="t('events.filters.to')">
          <template #default="{ attrs }">
            <input v-bind="attrs" v-model="localTo" type="datetime-local" :class="dateClass" />
          </template>
        </SkFormField>
      </template>
    </div>
    <div class="mt-4 flex flex-wrap gap-2">
      <Button type="submit" :label="t('events.filters.apply')" />
      <Button
        type="button"
        severity="secondary"
        :label="t('events.filters.reset')"
        @click="reset"
      />
    </div>
  </form>

  <p class="mb-2 text-sm text-sk-muted" role="status" data-testid="live-status">
    <i :class="['ti', live ? 'ti-antenna-bars-5' : 'ti-player-pause']" aria-hidden="true" />
    {{
      paused
        ? t('events.live.paused')
        : onFirstPage
          ? t('events.live.on', { seconds: POLL_MS / 1000 })
          : t('events.live.offFirstPage')
    }}
  </p>
  <p v-if="refreshError" role="alert" class="mb-2 text-sk-warning">
    <i class="ti ti-alert-triangle" aria-hidden="true" />
    {{ t('events.refreshFailed') }}
  </p>
  <p class="sr-only" aria-live="polite">{{ announcement }}</p>

  <p v-if="state === 'loading'" role="status">{{ t('events.loading') }}…</p>
  <div
    v-else-if="state === 'error'"
    role="alert"
    class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
  >
    <p>
      <i class="ti ti-alert-circle" aria-hidden="true" />
      {{ t('events.loadError') }}
    </p>
    <Button :label="t('common.actions.retry')" severity="secondary" @click="load()" />
  </div>
  <SkEmptyState
    v-else-if="rows.length === 0"
    icon="ti ti-search-off"
    :title="t('events.emptyTitle')"
    :description="t('events.emptyDescription')"
  />
  <template v-else>
    <div class="overflow-x-auto" tabindex="0" role="region" :aria-label="t('events.table.scroll')">
      <table class="w-full text-left" data-testid="events-table">
        <caption class="sr-only">
          {{
            t('events.table.caption')
          }}
        </caption>
        <thead>
          <tr class="border-b border-sk-border-strong">
            <th scope="col" class="p-2">{{ t('events.table.time') }}</th>
            <th scope="col" class="p-2">{{ t('events.table.site') }}</th>
            <th scope="col" class="p-2">{{ t('events.table.action') }}</th>
            <th scope="col" class="p-2">{{ t('events.table.request') }}</th>
            <th scope="col" class="p-2">{{ t('events.table.client') }}</th>
            <th scope="col" class="p-2">{{ t('events.table.rules') }}</th>
            <th scope="col" class="p-2">{{ t('events.table.status') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="e in rows"
            :key="e.id"
            class="border-b border-sk-border"
            :data-testid="`event-${e.id}`"
          >
            <th scope="row" class="p-2 font-normal">
              <RouterLink
                :to="{ name: 'event-detail', params: { id: e.id } }"
                class="text-sk-accent underline"
              >
                <time :datetime="e.ts">{{ formatTime(e.ts) }}</time>
                <span class="sr-only"> {{ t('events.table.open', { id: e.id }) }}</span>
              </RouterLink>
            </th>
            <td class="p-2">{{ e.siteId }}</td>
            <td class="p-2"><ActionBadge :action="e.action" /></td>
            <td class="max-w-xs break-all p-2 font-mono text-sm">{{ requestLabel(e) }}</td>
            <td class="p-2 font-mono text-sm">
              {{ e.client.ip }}<span v-if="e.client.country"> ({{ e.client.country }})</span>
            </td>
            <td class="p-2 font-mono text-sm">
              {{ rulesOf(e).length ? rulesOf(e).join(', ') : t('events.table.noRules') }}
            </td>
            <td class="p-2">{{ e.response.status ?? '' }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <nav class="mt-4 flex items-center gap-4" :aria-label="t('events.pager.label')">
      <Button
        type="button"
        severity="secondary"
        icon="ti ti-chevron-left"
        :label="t('events.pager.previous')"
        :disabled="onFirstPage"
        @click="newer"
      />
      <span class="text-sm text-sk-muted">{{ t('events.pager.page', { n: cursors.length }) }}</span>
      <Button
        type="button"
        severity="secondary"
        icon="ti ti-chevron-right"
        :label="t('events.pager.next')"
        :disabled="!nextCursor"
        @click="older"
      />
    </nav>
  </template>
</template>
