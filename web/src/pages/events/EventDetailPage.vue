<script setup lang="ts">
import Button from 'openvue/button'
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import { isApiError } from '@/api/errors'
import { useApi } from '@/api/useApi'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { formatTime } from '@/pages/history/format'
import ExclusionWizard from '@/pages/tuning/ExclusionWizard.vue'
import { useSessionStore } from '@/stores/session'
import ActionBadge from './ActionBadge.vue'
import { ruleIds, toView, type EventView } from './event'

const SIMILAR_LIMIT = 100
const DAY_MS = 24 * 3_600_000

const { t } = useI18n()
const route = useRoute()
const { client, call } = useApi()
const session = useSessionStore()
const wizardOpen = ref(false)

const event = ref<EventView>()
const state = ref<'loading' | 'ready' | 'missing' | 'error'>('loading')
const similar = ref<{ rule: string; count: number; capped: boolean }>()

const id = computed(() => String(route.params.id))

async function loadSimilar(e: EventView) {
  const rule = ruleIds(e)[0]
  similar.value = undefined
  if (!rule) return
  try {
    const res = await call(
      client.GET('/events', {
        params: {
          query: {
            rule_id: rule,
            ...(e.siteId ? { site: e.siteId } : {}),
            from: new Date(Date.now() - DAY_MS).toISOString(),
            limit: SIMILAR_LIMIT,
          },
        },
      }),
      { toast: false },
    )
    const others = res.data.items.filter((i) => i.id !== e.id).length
    similar.value = { rule, count: others, capped: res.data.next_cursor !== undefined }
  } catch (err) {
    // The count is a convenience; the event itself is already on screen.
    if (!isApiError(err)) throw err
  }
}

async function load() {
  state.value = 'loading'
  event.value = undefined
  try {
    const res = await call(client.GET('/events/{id}', { params: { path: { id: id.value } } }), {
      toast: false,
    })
    event.value = toView(res.data)
    state.value = 'ready'
    void loadSimilar(event.value)
  } catch (e) {
    if (!isApiError(e)) throw e
    state.value = e.kind === 'not_found' ? 'missing' : 'error'
  }
}
watch(id, load, { immediate: true })

const canExclude = computed(
  () =>
    session.can('config:write') &&
    event.value !== undefined &&
    event.value.siteId !== '' &&
    event.value.findings.some((f) => f.ruleId),
)

const dash = '–'
const show = (v: string | number | undefined) => (v === undefined || v === '' ? dash : String(v))

const summary = computed(() => {
  const e = event.value
  if (!e) return []
  return [
    ['id', e.id],
    ['ts', e.ts ? formatTime(e.ts) : ''],
    ['site', e.siteId],
    ['mode', e.mode],
    ['terminatedBy', e.terminatedBy],
    ['node', e.node],
    ['configVersion', e.configVersion],
    ['totalMs', e.timing.totalMs],
    ['wafMs', e.timing.wafMs],
  ] as [string, string | number | undefined][]
})
const requestRows = computed(() => {
  const e = event.value
  if (!e) return []
  return [
    ['method', e.request.method],
    ['host', e.request.host],
    ['path', e.request.path],
    ['query', e.request.query],
  ] as [string, string][]
})
const clientRows = computed(() => {
  const e = event.value
  if (!e) return []
  return [
    ['ip', e.client.ip],
    ['country', e.client.country],
    ['asn', e.client.asn],
    ['reputation', e.client.reputation],
  ] as [string, string | number | undefined][]
})
</script>

<template>
  <SkPageHeader
    :title="t('events.detailTitle')"
    :description="event ? `${event.request.method} ${event.request.path}` : undefined"
    :breadcrumbs="[{ label: t('events.title'), to: '/events' }, { label: id }]"
  >
    <template #actions>
      <Button
        v-if="canExclude"
        :label="t('tuning.wizard.open')"
        icon="ti ti-adjustments"
        data-testid="create-exclusion"
        @click="wizardOpen = true"
      />
    </template>
  </SkPageHeader>
  <ExclusionWizard
    v-if="canExclude && event"
    v-model:open="wizardOpen"
    :site="event.siteId"
    :event-id="event.id"
    :findings="event.findings"
  />

  <p v-if="state === 'loading'" role="status">{{ t('common.loading') }}…</p>
  <div
    v-else-if="state === 'missing' || state === 'error'"
    role="alert"
    class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
  >
    <p>{{ state === 'missing' ? t('events.detail.notFound') : t('events.detail.loadError') }}</p>
    <RouterLink to="/events" class="underline">{{ t('events.detail.back') }}</RouterLink>
    <Button
      v-if="state === 'error'"
      :label="t('common.actions.retry')"
      severity="secondary"
      @click="load"
    />
  </div>
  <div v-else-if="event" class="flex flex-col gap-6" data-testid="event-detail">
    <section aria-labelledby="ev-summary" class="rounded-sk-lg border border-sk-border p-4">
      <h2 id="ev-summary" class="mb-2 text-lg font-semibold">{{ t('events.detail.summary') }}</h2>
      <p class="mb-2"><ActionBadge :action="event.action" /></p>
      <dl class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1">
        <template v-for="[key, value] in summary" :key="key">
          <dt class="text-sk-muted">{{ t(`events.detail.fields.${key}`) }}</dt>
          <dd class="break-all font-mono text-sm">{{ show(value) }}</dd>
        </template>
      </dl>
    </section>

    <section aria-labelledby="ev-request" class="rounded-sk-lg border border-sk-border p-4">
      <h2 id="ev-request" class="mb-2 text-lg font-semibold">{{ t('events.detail.request') }}</h2>
      <dl class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1">
        <template v-for="[key, value] in requestRows" :key="key">
          <dt class="text-sk-muted">{{ t(`events.detail.fields.${key}`) }}</dt>
          <dd class="break-all font-mono text-sm" :data-testid="`request-${key}`">
            {{ show(value) }}
          </dd>
        </template>
      </dl>
      <h3 class="mb-1 mt-4 font-medium">{{ t('events.detail.fields.headers') }}</h3>
      <p v-if="!event.request.headers.length" class="text-sk-muted">
        {{ t('events.detail.none') }}
      </p>
      <div
        v-else
        class="overflow-x-auto"
        tabindex="0"
        role="region"
        :aria-label="t('events.detail.headersCaption')"
      >
        <table class="w-full text-left text-sm">
          <caption class="sr-only">
            {{
              t('events.detail.headersCaption')
            }}
          </caption>
          <tbody>
            <tr
              v-for="[name, value] in event.request.headers"
              :key="name"
              class="border-t border-sk-border"
            >
              <th scope="row" class="p-2 font-mono font-normal">{{ name }}</th>
              <td class="break-all p-2 font-mono" data-testid="request-header">{{ value }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <h3 class="mb-1 mt-4 font-medium">{{ t('events.detail.fields.body') }}</h3>
      <div
        v-if="event.request.body"
        class="overflow-x-auto whitespace-pre-wrap break-all rounded-sk border border-sk-border bg-sk-surface-muted p-3 text-sm font-mono"
        tabindex="0"
        role="region"
        :aria-label="t('events.detail.fields.body')"
        data-testid="request-body"
        v-text="event.request.body"
      />
      <p v-else class="text-sk-muted">{{ t('events.detail.none') }}</p>
    </section>

    <div class="grid gap-6 md:grid-cols-3">
      <section aria-labelledby="ev-response" class="rounded-sk-lg border border-sk-border p-4">
        <h2 id="ev-response" class="mb-2 text-lg font-semibold">
          {{ t('events.detail.response') }}
        </h2>
        <dl class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1">
          <dt class="text-sk-muted">{{ t('events.detail.fields.status') }}</dt>
          <dd class="font-mono text-sm">{{ show(event.response.status) }}</dd>
          <dt class="text-sk-muted">{{ t('events.detail.fields.bytes') }}</dt>
          <dd class="font-mono text-sm">{{ show(event.response.bytes) }}</dd>
        </dl>
      </section>
      <section aria-labelledby="ev-client" class="rounded-sk-lg border border-sk-border p-4">
        <h2 id="ev-client" class="mb-2 text-lg font-semibold">{{ t('events.detail.client') }}</h2>
        <dl class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1">
          <template v-for="[key, value] in clientRows" :key="key">
            <dt class="text-sk-muted">{{ t(`events.detail.fields.${key}`) }}</dt>
            <dd class="break-all font-mono text-sm">{{ show(value) }}</dd>
          </template>
        </dl>
      </section>
      <section aria-labelledby="ev-score" class="rounded-sk-lg border border-sk-border p-4">
        <h2 id="ev-score" class="mb-2 text-lg font-semibold">{{ t('events.detail.score') }}</h2>
        <dl class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1">
          <dt class="text-sk-muted">{{ t('events.detail.fields.inbound') }}</dt>
          <dd class="font-mono text-sm">{{ show(event.score.inbound) }}</dd>
          <dt class="text-sk-muted">{{ t('events.detail.fields.outbound') }}</dt>
          <dd class="font-mono text-sm">{{ show(event.score.outbound) }}</dd>
        </dl>
      </section>
    </div>

    <section aria-labelledby="ev-findings" class="rounded-sk-lg border border-sk-border p-4">
      <h2 id="ev-findings" class="mb-2 text-lg font-semibold">{{ t('events.detail.findings') }}</h2>
      <p v-if="!event.findings.length" class="text-sk-muted">{{ t('events.detail.none') }}</p>
      <div
        v-else
        class="overflow-x-auto"
        tabindex="0"
        role="region"
        :aria-label="t('events.detail.findingsCaption')"
      >
        <table class="w-full text-left text-sm" data-testid="findings-table">
          <caption class="sr-only">
            {{
              t('events.detail.findingsCaption')
            }}
          </caption>
          <thead>
            <tr class="border-b border-sk-border-strong">
              <th scope="col" class="p-2">{{ t('events.detail.cols.rule') }}</th>
              <th scope="col" class="p-2">{{ t('events.detail.cols.module') }}</th>
              <th scope="col" class="p-2">{{ t('events.detail.cols.severity') }}</th>
              <th scope="col" class="p-2">{{ t('events.detail.cols.score') }}</th>
              <th scope="col" class="p-2">{{ t('events.detail.cols.message') }}</th>
              <th scope="col" class="p-2">{{ t('events.detail.cols.target') }}</th>
              <th scope="col" class="p-2">{{ t('events.detail.cols.matched') }}</th>
              <th scope="col" class="p-2">{{ t('events.detail.cols.tags') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="(f, i) in event.findings"
              :key="i"
              class="border-b border-sk-border align-top"
            >
              <th scope="row" class="p-2 font-mono font-normal">
                <RouterLink
                  v-if="f.ruleId"
                  :to="{ name: 'events', query: { rule_id: f.ruleId } }"
                  class="text-sk-accent underline"
                  :aria-label="t('events.detail.ruleLink', { rule: f.ruleId })"
                >
                  {{ f.ruleId }}
                </RouterLink>
              </th>
              <td class="p-2">{{ f.module }}</td>
              <td class="p-2">{{ f.severity }}</td>
              <td class="p-2">{{ show(f.score) }}</td>
              <td class="p-2">{{ f.message }}</td>
              <td class="break-all p-2 font-mono">{{ f.target }}</td>
              <td class="break-all p-2 font-mono">{{ f.matched }}</td>
              <td class="p-2">{{ f.tags.join(', ') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section aria-labelledby="ev-similar" class="rounded-sk-lg border border-sk-border p-4">
      <h2 id="ev-similar" class="mb-2 text-lg font-semibold">{{ t('events.detail.similar') }}</h2>
      <p v-if="!similar" class="text-sk-muted">{{ t('events.detail.similarNone') }}</p>
      <p v-else data-testid="similar-count">
        {{
          t(similar.capped ? 'events.detail.similarMany' : 'events.detail.similarCount', {
            count: similar.count,
            rule: similar.rule,
          })
        }}
        <RouterLink
          :to="{ name: 'events', query: { rule_id: similar.rule, site: event.siteId } }"
          class="text-sk-accent underline"
        >
          {{ t('events.detail.similarLink') }}
        </RouterLink>
      </p>
    </section>
  </div>
</template>
