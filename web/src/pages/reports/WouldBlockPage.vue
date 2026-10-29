<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { isApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import SkStatusBadge from '@/components/SkStatusBadge.vue'
import { formatTime } from '@/pages/history/format'
import BlockConfirmDialog from '@/pages/sites/BlockConfirmDialog.vue'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'

type Site = components['schemas']['Site']
type Report = components['schemas']['WouldBlockReport']

const RANGES = { '24h': 86_400_000, '7d': 7 * 86_400_000, '30d': 30 * 86_400_000 } as const
type RangeKey = keyof typeof RANGES

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const toasts = useToastStore()
const { client, call, ifMatch } = useApi()

const sites = ref<Site[]>([])
const etag = ref<string>()
const report = ref<Report>()
const state = ref<'loading' | 'ready' | 'error' | 'nosites'>('loading')
const confirmBlock = ref(false)
const busy = ref(false)
let seq = 0

const canWrite = computed(() => session.can('config:write'))
const siteId = computed(() => {
  const q = route.query.site
  return typeof q === 'string' ? q : ''
})
const range = computed<RangeKey>(() => {
  const q = route.query.range
  return typeof q === 'string' && q in RANGES ? (q as RangeKey) : '7d'
})
const site = computed(() => sites.value.find((s) => s.id === siteId.value))
const mode = computed(() => site.value?.policy?.mode ?? 'off')

function bounds() {
  const to = new Date(Math.floor(Date.now() / 60_000) * 60_000)
  return { from: new Date(to.getTime() - RANGES[range.value]).toISOString(), to: to.toISOString() }
}

async function loadSites() {
  try {
    const res = await call(client.GET('/sites'), { toast: false })
    sites.value = res.data.items
    etag.value = res.etag
  } catch (e) {
    if (!isApiError(e)) throw e
    state.value = 'error'
    return false
  }
  if (!sites.value.length) {
    state.value = 'nosites'
    return false
  }
  if (!site.value) {
    const preferred = sites.value.find((s) => s.policy?.mode === 'detect') ?? sites.value[0]
    if (preferred) await router.replace({ query: { ...route.query, site: preferred.id } })
  }
  return true
}

async function loadReport() {
  if (!siteId.value) return
  const mine = ++seq
  state.value = 'loading'
  try {
    const res = await call(
      client.GET('/reports/would-block', {
        params: { query: { site: siteId.value, ...bounds() } },
      }),
      { toast: false },
    )
    if (mine !== seq) return
    report.value = res.data
    state.value = 'ready'
  } catch (e) {
    if (mine !== seq) return
    if (!isApiError(e)) throw e
    state.value = 'error'
  }
}

onMounted(async () => {
  if (await loadSites()) await loadReport()
})
watch([siteId, range], () => void loadReport())

function choose(key: 'site' | 'range', value: string | undefined) {
  void router.push({ query: { ...route.query, [key]: value ?? '' } })
}

async function exportCsv() {
  try {
    const res = await call(
      client.GET('/reports/would-block.csv', {
        params: { query: { site: siteId.value, ...bounds() } },
        parseAs: 'blob',
      }),
      { toast: false },
    )
    const url = URL.createObjectURL(res.data as unknown as Blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `would-block-${siteId.value}-${range.value}.csv`
    link.click()
    URL.revokeObjectURL(url)
    toasts.success(t('reports.export.done'))
  } catch (e) {
    if (!isApiError(e)) throw e
    toasts.error(t('reports.export.failed'))
  }
}

async function switchToBlock() {
  if (!etag.value) return
  busy.value = true
  try {
    const res = await call(
      client.PATCH('/sites/{site}', {
        params: { path: { site: siteId.value }, header: ifMatch(etag.value) },
        headers: { 'Content-Type': 'application/merge-patch+json' },
        body: { policy: { mode: 'block' } },
      }),
      { toast: false },
    )
    etag.value = res.etag ?? etag.value
    confirmBlock.value = false
    toasts.success(t('reports.switch.done', { site: siteId.value }))
    await loadSites()
  } catch (e) {
    confirmBlock.value = false
    toasts.error(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <SkPageHeader :title="t('reports.title')" :description="t('reports.description')" />

  <SkEmptyState
    v-if="state === 'nosites'"
    icon="ti ti-world-off"
    :title="t('reports.noSites')"
    :description="t('reports.noSitesDescription')"
  />
  <template v-else>
    <div class="mb-6 flex flex-wrap items-end gap-4">
      <SkFormField :label="t('reports.site')">
        <template #default="{ attrs }">
          <SelectControl
            v-bind="attrs"
            :model-value="siteId || undefined"
            :options="sites.map((s) => ({ value: s.id, label: s.name || s.id }))"
            @update:model-value="choose('site', $event)"
          />
        </template>
      </SkFormField>
      <SkFormField :label="t('reports.range')">
        <template #default="{ attrs }">
          <SelectControl
            v-bind="attrs"
            :model-value="range"
            :options="
              (Object.keys(RANGES) as RangeKey[]).map((k) => ({
                value: k,
                label: t(`reports.ranges.${k}`),
              }))
            "
            @update:model-value="choose('range', $event)"
          />
        </template>
      </SkFormField>
      <p v-if="site" class="flex items-center gap-2 pb-2">
        <span class="text-sk-muted">{{ t('reports.mode') }}</span>
        <SkStatusBadge :mode="mode" />
      </p>
    </div>

    <p v-if="state === 'loading'" role="status">{{ t('reports.loading') }}…</p>
    <div
      v-else-if="state === 'error'"
      role="alert"
      class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
    >
      <p>{{ t('reports.loadError') }}</p>
      <Button :label="t('common.actions.retry')" severity="secondary" @click="loadReport" />
    </div>
    <template v-else-if="report">
      <p v-if="site && mode !== 'detect'" class="mb-4 text-sk-muted">
        <i class="ti ti-info-circle" aria-hidden="true" /> {{ t('reports.notDetect') }}
      </p>
      <section class="mb-6" aria-labelledby="wb-total">
        <h2 id="wb-total" class="text-sm font-medium text-sk-muted">{{ t('reports.total') }}</h2>
        <p class="text-3xl font-semibold" data-testid="wb-total-count">{{ report.total }}</p>
        <p v-if="report.truncated" class="mt-1 text-sk-warning" role="status">
          <i class="ti ti-alert-triangle" aria-hidden="true" /> {{ t('reports.truncated') }}
        </p>
        <div class="mt-3 flex flex-wrap gap-2">
          <Button
            type="button"
            severity="secondary"
            icon="ti ti-download"
            :label="t('reports.export.label')"
            @click="exportCsv"
          />
          <Button
            v-if="canWrite && mode === 'detect'"
            type="button"
            severity="danger"
            icon="ti ti-shield-lock"
            :label="t('reports.switch.label')"
            @click="confirmBlock = true"
          />
        </div>
      </section>

      <SkEmptyState
        v-if="report.total === 0"
        icon="ti ti-shield-check"
        :title="t('reports.clean.title')"
        :description="t('reports.clean.description')"
      />
      <div v-else class="flex flex-col gap-8">
        <div class="grid gap-8 lg:grid-cols-2">
          <section aria-labelledby="wb-rules">
            <h2 id="wb-rules" class="mb-2 text-lg font-semibold">
              {{ t('reports.byRule.title') }}
            </h2>
            <table class="w-full text-left" data-testid="by-rule">
              <caption class="sr-only">
                {{
                  t('reports.byRule.caption')
                }}
              </caption>
              <thead>
                <tr class="border-b border-sk-border-strong">
                  <th scope="col" class="p-2">{{ t('reports.byRule.rule') }}</th>
                  <th scope="col" class="p-2">{{ t('reports.byRule.count') }}</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="r in report.by_rule" :key="r.rule_id" class="border-b border-sk-border">
                  <th scope="row" class="p-2 font-mono font-normal">
                    <RouterLink
                      :to="{ name: 'events', query: { rule_id: r.rule_id, site: siteId } }"
                      class="text-sk-accent underline"
                    >
                      {{ r.rule_id }}
                    </RouterLink>
                  </th>
                  <td class="p-2">{{ r.count }}</td>
                </tr>
              </tbody>
            </table>
          </section>
          <section aria-labelledby="wb-paths">
            <h2 id="wb-paths" class="mb-2 text-lg font-semibold">
              {{ t('reports.byPath.title') }}
            </h2>
            <table class="w-full text-left" data-testid="by-path">
              <caption class="sr-only">
                {{
                  t('reports.byPath.caption')
                }}
              </caption>
              <thead>
                <tr class="border-b border-sk-border-strong">
                  <th scope="col" class="p-2">{{ t('reports.byPath.path') }}</th>
                  <th scope="col" class="p-2">{{ t('reports.byPath.count') }}</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="p in report.by_path" :key="p.path" class="border-b border-sk-border">
                  <th scope="row" class="break-all p-2 font-mono font-normal">{{ p.path }}</th>
                  <td class="p-2">{{ p.count }}</td>
                </tr>
              </tbody>
            </table>
          </section>
        </div>

        <section aria-labelledby="wb-requests">
          <h2 id="wb-requests" class="mb-2 text-lg font-semibold">
            {{ t('reports.requests.title') }}
          </h2>
          <div
            class="overflow-x-auto"
            tabindex="0"
            role="region"
            :aria-label="t('reports.requests.caption')"
          >
            <table class="w-full text-left" data-testid="wb-requests">
              <caption class="sr-only">
                {{
                  t('reports.requests.caption')
                }}
              </caption>
              <thead>
                <tr class="border-b border-sk-border-strong">
                  <th scope="col" class="p-2">{{ t('reports.requests.time') }}</th>
                  <th scope="col" class="p-2">{{ t('reports.requests.client') }}</th>
                  <th scope="col" class="p-2">{{ t('reports.requests.request') }}</th>
                  <th scope="col" class="p-2">{{ t('reports.requests.rules') }}</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="r in report.requests"
                  :key="r.event_id"
                  class="border-b border-sk-border"
                >
                  <th scope="row" class="p-2 font-normal">
                    <RouterLink
                      :to="{ name: 'event-detail', params: { id: r.event_id } }"
                      class="text-sk-accent underline"
                    >
                      <time :datetime="r.ts">{{ formatTime(r.ts) }}</time>
                      <span class="sr-only">
                        {{ t('reports.requests.open', { id: r.event_id }) }}</span
                      >
                    </RouterLink>
                  </th>
                  <td class="p-2 font-mono text-sm">{{ r.client_ip }}</td>
                  <td class="break-all p-2 font-mono text-sm">{{ r.method }} {{ r.path }}</td>
                  <td class="p-2 font-mono text-sm">{{ r.rule_ids.join(', ') }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </template>
  </template>

  <BlockConfirmDialog
    v-if="canWrite"
    v-model:open="confirmBlock"
    :site-name="site?.name || siteId"
    :busy="busy"
    @confirm="switchToBlock"
  />
</template>
