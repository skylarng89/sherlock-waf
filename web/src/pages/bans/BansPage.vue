<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { absoluteTime, relativeTime } from '@/pages/access/time'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import CreateBanForm from './CreateBanForm.vue'

type Ban = components['schemas']['Ban']

const REFRESH_MS = 30_000

const { t } = useI18n()
const session = useSessionStore()
const toasts = useToastStore()
const { client, call } = useApi()
const canWrite = computed(() => session.can('config:write'))

const bans = ref<Ban[]>([])
const state = ref<'loading' | 'ready' | 'error'>('loading')
const refreshError = ref(false)
const paused = ref(false)
const now = ref(Date.now())
const sites = ref<string[]>([])
const toLift = ref<Ban>()
const busy = ref(false)
const announcement = ref('')
let timer: ReturnType<typeof setInterval> | undefined

async function load(silent = false) {
  if (!silent) state.value = 'loading'
  try {
    bans.value = (await call(client.GET('/bans'), { toast: false })).data.items
    state.value = 'ready'
    refreshError.value = false
  } catch {
    // A failed background refresh keeps the table that is already shown.
    if (silent && state.value === 'ready') refreshError.value = true
    else state.value = 'error'
  }
  now.value = Date.now()
}

async function loadSites() {
  try {
    const res = await call(client.GET('/sites'), { toast: false })
    sites.value = res.data.items.map((s) => s.id)
  } catch {
    sites.value = []
  }
}

function startTimer() {
  stopTimer()
  timer = setInterval(() => void load(true), REFRESH_MS)
}
function stopTimer() {
  if (timer !== undefined) clearInterval(timer)
  timer = undefined
}

function togglePause() {
  paused.value = !paused.value
  if (paused.value) stopTimer()
  else {
    void load(true)
    startTimer()
  }
}

onMounted(() => {
  void load()
  void loadSites()
  startTimer()
})
onBeforeUnmount(stopTimer)

async function lift() {
  const ban = toLift.value
  if (!ban) return
  busy.value = true
  try {
    await call(client.DELETE('/bans/{id}', { params: { path: { id: ban.id } } }), { toast: false })
    toLift.value = undefined
    toasts.success(t('bans.lifted', { ip: ban.ip }))
    announcement.value = t('bans.lifted', { ip: ban.ip })
    await load(true)
  } catch (e) {
    toLift.value = undefined
    // 404: somebody lifted it already; the refresh shows the truth.
    if (isApiError(e) && e.kind === 'not_found') await load(true)
    toasts.error(e)
  } finally {
    busy.value = false
  }
}

function onCreated() {
  void load(true)
}
</script>

<template>
  <SkPageHeader :title="t('bans.title')" :description="t('bans.description')">
    <template #actions>
      <Button
        type="button"
        severity="secondary"
        :icon="paused ? 'ti ti-player-play' : 'ti ti-player-pause'"
        :label="paused ? t('bans.resume') : t('bans.pause')"
        :aria-pressed="paused"
        @click="togglePause"
      />
      <Button
        type="button"
        severity="secondary"
        icon="ti ti-refresh"
        :label="t('bans.refresh')"
        @click="load(true)"
      />
    </template>
  </SkPageHeader>

  <p v-if="!canWrite" role="status" class="mb-4 text-sk-muted">
    <i class="ti ti-lock" aria-hidden="true" />
    {{ t('bans.readOnly') }}
  </p>

  <CreateBanForm v-if="canWrite" class="mb-8" :sites="sites" @created="onCreated" />

  <p class="mb-2 text-sm text-sk-muted" role="status">
    {{ paused ? t('bans.pausedNote') : t('bans.autoRefreshNote') }}
  </p>
  <p v-if="refreshError" role="alert" class="mb-2 text-sk-warning">
    <i class="ti ti-alert-triangle" aria-hidden="true" />
    {{ t('bans.refreshFailed') }}
  </p>
  <p class="sr-only" aria-live="polite">{{ announcement }}</p>

  <p v-if="state === 'loading'" role="status">{{ t('common.loading') }}…</p>
  <div
    v-else-if="state === 'error'"
    role="alert"
    class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
  >
    <p>
      <i class="ti ti-alert-circle" aria-hidden="true" />
      {{ t('bans.loadFailed') }}
    </p>
    <Button :label="t('common.actions.retry')" severity="secondary" @click="load()" />
  </div>
  <SkEmptyState
    v-else-if="bans.length === 0"
    icon="ti ti-shield-check"
    :title="t('bans.emptyTitle')"
    :description="t('bans.emptyDescription')"
  />
  <div v-else class="overflow-x-auto" tabindex="0" role="region" :aria-label="t('bans.scroll')">
    <table class="w-full text-left" data-testid="bans-table">
      <caption class="sr-only">
        {{
          t('bans.caption')
        }}
      </caption>
      <thead>
        <tr class="border-b border-sk-border-strong">
          <th scope="col" class="p-2">{{ t('bans.cols.ip') }}</th>
          <th scope="col" class="p-2">{{ t('bans.cols.scope') }}</th>
          <th scope="col" class="p-2">{{ t('bans.cols.source') }}</th>
          <th scope="col" class="p-2">{{ t('bans.cols.reason') }}</th>
          <th scope="col" class="p-2">{{ t('bans.cols.createdBy') }}</th>
          <th scope="col" class="p-2">{{ t('bans.cols.until') }}</th>
          <th v-if="canWrite" scope="col" class="p-2">{{ t('bans.cols.controls') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="b in bans"
          :key="b.id"
          class="border-b border-sk-border"
          :data-testid="`ban-${b.id}`"
        >
          <th scope="row" class="p-2 font-mono text-sm font-normal">{{ b.ip }}</th>
          <td class="p-2">
            <span class="inline-flex items-center gap-1">
              <i :class="['ti', b.site_id ? 'ti-world' : 'ti-world-www']" aria-hidden="true" />
              {{ b.site_id ? t('bans.scope.site', { site: b.site_id }) : t('bans.scope.all') }}
            </span>
          </td>
          <td class="p-2">
            <span
              class="inline-flex items-center gap-1 rounded-full border border-current/30 bg-sk-surface-muted px-2 py-0.5 text-xs font-medium"
            >
              <i
                :class="[
                  'ti',
                  b.source === 'manual'
                    ? 'ti-user'
                    : b.source === 'auto'
                      ? 'ti-robot'
                      : 'ti-shield-chevron',
                ]"
                aria-hidden="true"
              />
              {{ t(`bans.source.${b.source}`) }}
            </span>
          </td>
          <td class="p-2">{{ b.reason }}</td>
          <td class="p-2">{{ b.created_by }}</td>
          <td class="p-2">
            <time :datetime="b.until">{{ relativeTime(b.until, now) }}</time>
            <span class="block text-sm text-sk-muted">{{ absoluteTime(b.until) }}</span>
          </td>
          <td v-if="canWrite" class="p-2">
            <button
              type="button"
              class="rounded-sk border border-sk-border-strong px-2 py-1"
              :aria-label="t('bans.liftNamed', { ip: b.ip })"
              @click="toLift = b"
            >
              <i class="ti ti-lock-open" aria-hidden="true" />
              {{ t('bans.lift') }}
            </button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <SkConfirmDialog
    v-if="canWrite"
    :open="toLift !== undefined"
    danger
    :busy="busy"
    :title="t('bans.confirmTitle', { ip: toLift?.ip ?? '' })"
    :message="t('bans.confirmMessage')"
    :confirm-label="t('bans.lift')"
    @update:open="toLift = undefined"
    @confirm="lift"
  />
</template>
