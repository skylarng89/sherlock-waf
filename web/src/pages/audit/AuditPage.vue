<script setup lang="ts">
import Button from 'openvue/button'
import InputText from 'openvue/inputtext'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'

type Entry = components['schemas']['AuditEntry']
type Head = NonNullable<components['schemas']['SystemInfo']['audit_head']>

const PAGE_SIZE = 50

const { t } = useI18n()
const { client, call } = useApi()

const entries = ref<Entry[]>([])
const nextBefore = ref<number>()
const loading = ref(true)
const loadingOlder = ref(false)
const loadError = ref('')
const olderStatus = ref('')
const head = ref<Head>()
const headUnavailable = ref(false)
const copyStatus = ref('')
const expanded = ref(new Set<string>())

const actionFilter = ref('')
const actorFilter = ref('')

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' })

const actorTypes = computed(() => [...new Set(entries.value.map((e) => e.actor_type))].sort())
const filtered = computed(() => {
  const needle = actionFilter.value.trim().toLowerCase()
  return entries.value.filter(
    (e) =>
      (!needle || e.action.toLowerCase().includes(needle)) &&
      (!actorFilter.value || e.actor_type === actorFilter.value),
  )
})
const filtering = computed(() => actionFilter.value.trim() !== '' || actorFilter.value !== '')

async function fetchPage(before?: number) {
  const res = await call(
    client.GET('/audit', {
      params: {
        query: { limit: PAGE_SIZE, ...(before !== undefined ? { before_seq: before } : {}) },
      },
    }),
    { toast: false },
  )
  nextBefore.value = res.data.next_before_seq
  return res.data.items
}

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    entries.value = await fetchPage()
  } catch (e) {
    loadError.value = isApiError(e) ? (e.detail ?? e.title) : t('audit.loadFailed')
  } finally {
    loading.value = false
  }
}

async function loadHead() {
  try {
    head.value = (await call(client.GET('/system/info'), { toast: false })).data.audit_head
  } catch {
    // The head is a convenience; a role without system:read simply does not see it.
    headUnavailable.value = true
  }
}

async function loadOlder() {
  if (nextBefore.value === undefined || loadingOlder.value) return
  loadingOlder.value = true
  olderStatus.value = ''
  try {
    const items = await fetchPage(nextBefore.value)
    entries.value = [...entries.value, ...items]
    olderStatus.value = t('audit.loadedMore', { n: items.length })
  } catch (e) {
    loadError.value = isApiError(e) ? (e.detail ?? e.title) : t('audit.loadFailed')
  } finally {
    loadingOlder.value = false
  }
}

onMounted(() => {
  void load()
  void loadHead()
})

function toggle(id: string) {
  const next = new Set(expanded.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  expanded.value = next
}

function clearFilters() {
  actionFilter.value = ''
  actorFilter.value = ''
}

async function copyHash() {
  try {
    await navigator.clipboard.writeText(head.value?.hash ?? '')
    copyStatus.value = t('audit.head.copied')
  } catch {
    copyStatus.value = t('audit.head.copyFailed')
  }
}

const objectOf = (e: Entry) => [e.object_type, e.object_id].filter(Boolean).join(' / ') || '—'
const detailsOf = (e: Entry) => JSON.stringify(e.details ?? {}, null, 2)
const hasDetails = (e: Entry) => e.details !== undefined && Object.keys(e.details).length > 0
</script>

<template>
  <SkPageHeader :title="t('audit.title')" :description="t('audit.description')" />

  <div class="flex flex-col gap-8">
    <section aria-labelledby="audit-head-heading" class="flex flex-col gap-2">
      <h2 id="audit-head-heading" class="text-lg font-semibold">{{ t('audit.head.heading') }}</h2>
      <template v-if="head">
        <dl class="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1">
          <dt class="font-medium">{{ t('audit.head.seq') }}</dt>
          <dd data-testid="head-seq">{{ head.seq }}</dd>
          <dt class="font-medium">{{ t('audit.head.hash') }}</dt>
          <dd class="break-all font-mono text-sm" data-testid="head-hash">{{ head.hash }}</dd>
        </dl>
        <div class="flex flex-col items-start gap-1">
          <Button
            type="button"
            outlined
            size="small"
            :label="t('audit.head.copy')"
            @click="copyHash"
          />
          <p role="status" class="text-sm">{{ copyStatus }}</p>
        </div>
      </template>
      <p v-else-if="headUnavailable" class="text-sk-muted">{{ t('audit.head.unavailable') }}</p>
      <p v-else class="text-sk-muted">{{ t('audit.head.empty') }}</p>
      <p class="max-w-prose text-sm text-sk-muted">{{ t('audit.head.help') }}</p>
    </section>

    <section aria-labelledby="audit-filters-heading" class="flex flex-col gap-3">
      <h2 id="audit-filters-heading" class="text-lg font-semibold">
        {{ t('audit.filters.heading') }}
      </h2>
      <form class="flex flex-wrap items-start gap-4" @submit.prevent>
        <SkFormField :label="t('audit.filters.action')" :help="t('audit.filters.actionHelp')">
          <template #default="{ attrs }">
            <InputText
              v-bind="attrs"
              v-model="actionFilter"
              name="action"
              autocomplete="off"
              spellcheck="false"
            />
          </template>
        </SkFormField>
        <SkFormField :label="t('audit.filters.actor')">
          <template #default="{ attrs }">
            <select
              v-bind="attrs"
              v-model="actorFilter"
              name="actor_type"
              class="rounded-sk border border-sk-border-strong bg-sk-surface px-3 py-2 text-sk-text"
            >
              <option value="">{{ t('audit.filters.allActors') }}</option>
              <option v-for="a in actorTypes" :key="a" :value="a">{{ a }}</option>
            </select>
          </template>
        </SkFormField>
        <div class="self-center pt-2">
          <Button
            type="button"
            outlined
            :label="t('audit.filters.clear')"
            :disabled="!filtering"
            @click="clearFilters"
          />
        </div>
      </form>
      <p class="text-sm text-sk-muted">
        <i class="ti ti-info-circle" aria-hidden="true" />
        {{ t('audit.filters.clientSide') }}
      </p>
    </section>

    <section :aria-label="t('audit.caption')" class="flex flex-col gap-3">
      <p v-if="loading" role="status">{{ t('audit.loading') }}</p>
      <div
        v-else-if="loadError"
        role="alert"
        class="flex flex-col items-start gap-2 rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
      >
        <p>
          <i class="ti ti-alert-circle" aria-hidden="true" />
          {{ t('audit.loadFailed') }} {{ loadError }}
        </p>
        <Button :label="t('common.actions.retry')" @click="load" />
      </div>
      <SkEmptyState
        v-else-if="entries.length === 0"
        icon="ti ti-list-search"
        :title="t('audit.emptyTitle')"
        :description="t('audit.emptyDescription')"
      />
      <template v-else>
        <p role="status" class="text-sm text-sk-muted">
          {{ t('audit.filters.summary', { shown: filtered.length, loaded: entries.length }) }}
        </p>
        <p v-if="filtered.length === 0" class="text-sk-muted">{{ t('audit.noMatches') }}</p>
        <div
          v-else
          class="overflow-x-auto"
          tabindex="0"
          role="region"
          :aria-label="t('audit.caption')"
        >
          <table class="w-full text-left text-sm">
            <caption class="sr-only">
              {{
                t('audit.caption')
              }}
            </caption>
            <thead>
              <tr class="border-b border-sk-border-strong">
                <th scope="col" class="p-2">{{ t('audit.columns.seq') }}</th>
                <th scope="col" class="p-2">{{ t('audit.columns.time') }}</th>
                <th scope="col" class="p-2">{{ t('audit.columns.actor') }}</th>
                <th scope="col" class="p-2">{{ t('audit.columns.action') }}</th>
                <th scope="col" class="p-2">{{ t('audit.columns.object') }}</th>
                <th scope="col" class="p-2">{{ t('audit.columns.ip') }}</th>
                <th scope="col" class="p-2">{{ t('audit.columns.details') }}</th>
              </tr>
            </thead>
            <tbody>
              <template v-for="e in filtered" :key="e.id">
                <tr class="border-b border-sk-border align-top" :data-testid="`audit-${e.seq}`">
                  <th scope="row" class="p-2 font-mono">{{ e.seq }}</th>
                  <td class="p-2">{{ dateFormat.format(new Date(e.at)) }}</td>
                  <td class="p-2">{{ e.actor_type }}: {{ e.actor_id }}</td>
                  <td class="p-2 font-mono">{{ e.action }}</td>
                  <td class="p-2">{{ objectOf(e) }}</td>
                  <td class="p-2">{{ e.ip ?? '—' }}</td>
                  <td class="p-2">
                    <Button
                      type="button"
                      outlined
                      size="small"
                      :label="expanded.has(e.id) ? t('audit.collapse') : t('audit.expand')"
                      :aria-expanded="expanded.has(e.id)"
                      :aria-controls="`audit-detail-${e.seq}`"
                      :aria-label="
                        t(expanded.has(e.id) ? 'audit.collapseLabel' : 'audit.expandLabel', {
                          seq: e.seq,
                        })
                      "
                      @click="toggle(e.id)"
                    />
                  </td>
                </tr>
                <tr v-if="expanded.has(e.id)" class="border-b border-sk-border bg-sk-surface-muted">
                  <td :id="`audit-detail-${e.seq}`" colspan="7" class="p-3">
                    <dl class="mb-2 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1">
                      <dt class="font-medium">{{ t('audit.entryId') }}</dt>
                      <dd class="break-all font-mono">{{ e.id }}</dd>
                      <dt class="font-medium">{{ t('audit.hash') }}</dt>
                      <dd class="break-all font-mono">{{ e.hash }}</dd>
                    </dl>
                    <pre
                      v-if="hasDetails(e)"
                      class="overflow-x-auto whitespace-pre-wrap break-all font-mono"
                      v-text="detailsOf(e)"
                    />
                    <p v-else class="text-sk-muted">{{ t('audit.noDetails') }}</p>
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>
        <div class="flex flex-col items-start gap-2">
          <Button
            v-if="nextBefore !== undefined"
            type="button"
            :label="loadingOlder ? t('audit.loadingOlder') : t('audit.loadOlder')"
            :loading="loadingOlder"
            @click="loadOlder"
          />
          <p v-else class="text-sk-muted">{{ t('audit.noOlder') }}</p>
          <p role="status" class="text-sm">{{ olderStatus }}</p>
        </div>
      </template>
    </section>
  </div>
</template>
