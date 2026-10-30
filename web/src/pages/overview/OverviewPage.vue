<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import SkStatusBadge from '@/components/SkStatusBadge.vue'
import BotStats from '@/pages/bot/BotStats.vue'
import { useSessionStore } from '@/stores/session'
import CoveredCvesTile from '@/pages/tuning/CoveredCvesTile.vue'
import TrafficChart from './TrafficChart.vue'

type Site = components['schemas']['Site']
type SystemInfo = components['schemas']['SystemInfo']

const REFRESH_MS = 30_000

const { t } = useI18n()
const { client, call } = useApi()
const session = useSessionStore()

const sites = ref<Site[]>()
const info = ref<SystemInfo>()
const failed = ref(false)
const loading = ref(true)
let timer: ReturnType<typeof setInterval> | undefined

const canSites = computed(() => session.can('config:read'))
const canInfo = computed(() => session.can('system:read'))
const canEvents = computed(() => session.can('events:read'))

const modeCounts = computed(() => {
  const counts = { block: 0, detect: 0, off: 0, inherited: 0 }
  for (const s of sites.value ?? []) counts[s.policy?.mode ?? 'inherited']++
  return counts
})
const siteIds = computed(() => (sites.value ?? []).map((s) => s.id))

async function load() {
  const jobs: Promise<void>[] = []
  if (canSites.value) {
    jobs.push(
      call(client.GET('/sites'), { toast: false }).then((r) => {
        sites.value = r.data.items
      }),
    )
  }
  if (canInfo.value) {
    jobs.push(
      call(client.GET('/system/info'), { toast: false }).then((r) => {
        info.value = r.data
      }),
    )
  }
  const results = await Promise.allSettled(jobs)
  failed.value = results.some((r) => r.status === 'rejected')
  for (const r of results) {
    if (r.status === 'rejected' && !isApiError(r.reason)) throw r.reason
  }
  loading.value = false
}

onMounted(() => {
  void load()
  timer = setInterval(() => void load(), REFRESH_MS)
})
onBeforeUnmount(() => timer && clearInterval(timer))
</script>

<template>
  <SkPageHeader :title="t('overview.title')" :description="t('overview.description')" />

  <p v-if="loading && (canSites || canInfo)" role="status" class="text-sk-muted">
    {{ t('overview.loading') }}
  </p>
  <p v-if="failed" role="alert" class="mb-4 text-sk-danger">{{ t('overview.loadError') }}</p>

  <div class="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
    <section
      v-if="canSites"
      aria-labelledby="card-sites"
      class="rounded-sk-lg border border-sk-border bg-sk-surface p-4"
    >
      <h2 id="card-sites" class="text-sm font-medium text-sk-muted">
        {{ t('overview.cards.sites') }}
      </h2>
      <template v-if="sites">
        <p class="text-2xl font-semibold" data-testid="sites-total">
          {{ t('overview.cards.sitesTotal', sites.length) }}
        </p>
        <p v-if="!sites.length" class="text-sk-muted">{{ t('overview.cards.noSites') }}</p>
        <ul v-else class="mt-2 flex flex-wrap gap-2">
          <li v-for="m in ['block', 'detect', 'off'] as const" :key="m">
            <SkStatusBadge
              :mode="m"
              :label="
                t('overview.cards.modeCount', {
                  mode: t(`common.status.mode.${m}`),
                  count: modeCounts[m],
                })
              "
            />
          </li>
          <li v-if="modeCounts.inherited">
            {{
              t('overview.cards.modeCount', {
                mode: t('overview.cards.inherited'),
                count: modeCounts.inherited,
              })
            }}
          </li>
        </ul>
      </template>
    </section>

    <CoveredCvesTile v-if="canSites" />

    <template v-if="canInfo && info">
      <section
        aria-labelledby="card-status"
        class="rounded-sk-lg border border-sk-border bg-sk-surface p-4"
      >
        <h2 id="card-status" class="text-sm font-medium text-sk-muted">
          {{ t('overview.cards.ready') }}
        </h2>
        <p class="mt-1">
          <SkStatusBadge
            :state="info.ready ? 'ok' : 'error'"
            :label="info.ready ? t('overview.cards.ready_yes') : t('overview.cards.ready_no')"
          />
        </p>
        <dl class="mt-2 grid grid-cols-[max-content_1fr] gap-x-4 text-sm">
          <dt class="text-sk-muted">{{ t('overview.cards.version') }}</dt>
          <dd data-testid="sherlock-version">{{ info.version }}</dd>
          <dt class="text-sk-muted">{{ t('overview.cards.database') }}</dt>
          <dd data-testid="database">{{ info.database }}</dd>
        </dl>
      </section>
      <section
        aria-labelledby="card-config"
        class="rounded-sk-lg border border-sk-border bg-sk-surface p-4"
      >
        <h2 id="card-config" class="text-sm font-medium text-sk-muted">
          {{ t('overview.cards.crs') }}
        </h2>
        <p class="text-2xl font-semibold" data-testid="crs-version">{{ info.crs_version }}</p>
        <p class="mt-2 text-sm">
          <span class="text-sk-muted">{{ t('overview.cards.configVersion') }}: </span>
          <code data-testid="config-version">{{
            info.config_version || t('overview.cards.unknown')
          }}</code>
        </p>
      </section>
    </template>
    <BotStats v-if="canEvents" />
  </div>

  <TrafficChart v-if="canEvents" :sites="siteIds" />
  <SkEmptyState
    v-else
    icon="ti ti-lock"
    :title="t('overview.reduced.title')"
    :description="t('overview.reduced.description')"
  />
</template>
