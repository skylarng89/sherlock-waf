<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import Button from 'openvue/button'
import type { components } from '@/api/schema'
import { isApiError, isStale } from '@/api/errors'
import { useApi } from '@/api/useApi'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import DiffView from './DiffView.vue'
import { formatTime } from './format'
import { etagToId, useCurrentVersion } from './useCurrentVersion'

type VersionDetail = components['schemas']['VersionDetail']

const { t } = useI18n()
const { client, call, ifMatch } = useApi()
const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const toasts = useToastStore()
const head = useCurrentVersion()

const id = computed(() => String(route.params.id))
const version = ref<VersionDetail>()
const loading = ref(true)
const loadError = ref(false)
const confirmOpen = ref(false)
const busy = ref(false)
const stale = ref(false)
const refused = ref<string[]>([])
const noHead = ref(false)

const isCurrent = computed(() => etagToId(head.etag.value) === id.value)
const snapshotText = computed(() =>
  version.value ? JSON.stringify(version.value.snapshot, null, 2) : '',
)

async function load() {
  loading.value = true
  loadError.value = false
  stale.value = false
  refused.value = []
  try {
    const [res] = await Promise.all([
      call(client.GET('/config/versions/{id}', { params: { path: { id: id.value } } }), {
        toast: false,
      }),
      head.refresh().catch(() => undefined),
    ])
    version.value = res.data
  } catch (e) {
    if (!isApiError(e)) throw e
    loadError.value = true
  } finally {
    loading.value = false
  }
}

function refusalMessages(e: { fieldErrors: Record<string, string[]>; detail?: string }): string[] {
  const out = Object.entries(e.fieldErrors).flatMap(([path, msgs]) =>
    msgs.map((m) => (path ? `${path}: ${m}` : m)),
  )
  if (!out.length && e.detail) out.push(e.detail)
  return out
}

async function rollback() {
  const etag = head.etag.value
  if (!etag) {
    confirmOpen.value = false
    noHead.value = true
    return
  }
  busy.value = true
  stale.value = false
  refused.value = []
  noHead.value = false
  try {
    await call(
      client.POST('/config/versions/{id}/rollback', {
        params: { path: { id: id.value }, header: ifMatch(etag) },
      }),
      { toast: false },
    )
    confirmOpen.value = false
    toasts.success(t('history.rollback.success', { id: id.value }))
    await router.push({ name: 'history' })
  } catch (e) {
    confirmOpen.value = false
    if (isStale(e)) stale.value = true
    else if (isApiError(e) && e.status === 422) refused.value = refusalMessages(e)
    else toasts.error(e)
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <SkPageHeader
    :title="t('history.detailTitle')"
    :description="version ? t('history.detail.breadcrumb', { id: version.id }) : undefined"
    :breadcrumbs="[
      { label: t('history.title'), to: '/history' },
      { label: t('history.detail.breadcrumb', { id }) },
    ]"
  >
    <template #actions>
      <Button
        v-if="version && session.can('config:write')"
        type="button"
        :label="t('history.rollback.action')"
        :disabled="isCurrent || busy"
        @click="confirmOpen = true"
      />
    </template>
  </SkPageHeader>

  <p v-if="loading" role="status" class="text-sk-muted">{{ t('history.detail.loading') }}</p>
  <div
    v-else-if="loadError || !version"
    role="alert"
    class="flex items-center gap-3 rounded-sk-lg border border-sk-danger bg-sk-danger-bg p-4 text-sk-danger"
  >
    <span>{{ t('history.detail.loadError') }}</span>
    <Button type="button" :label="t('common.actions.retry')" severity="secondary" @click="load" />
  </div>
  <div v-else class="flex flex-col gap-6">
    <div
      v-if="stale"
      role="alert"
      class="flex items-center gap-3 rounded-sk-lg border border-sk-warning bg-sk-warning-bg p-4 text-sk-warning"
    >
      <i class="ti ti-alert-triangle" aria-hidden="true" />
      <span>{{ t('history.rollback.stale') }}</span>
      <Button
        type="button"
        :label="t('common.actions.reload')"
        severity="secondary"
        @click="load"
      />
    </div>
    <div
      v-if="refused.length"
      role="alert"
      class="rounded-sk-lg border border-sk-danger bg-sk-danger-bg p-4 text-sk-danger"
    >
      <p class="font-medium">{{ t('history.rollback.refused') }}</p>
      <p>{{ t('history.rollback.refusedDetail') }}</p>
      <ul class="ml-6 list-disc">
        <li v-for="m in refused" :key="m">{{ m }}</li>
      </ul>
    </div>
    <p v-if="noHead" role="alert" class="text-sk-danger">{{ t('history.rollback.noHead') }}</p>

    <section aria-labelledby="meta-title">
      <h2 id="meta-title" class="mb-2 text-lg font-medium">{{ t('history.detail.metadata') }}</h2>
      <dl class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1">
        <dt class="text-sk-muted">{{ t('history.detail.id') }}</dt>
        <dd>
          <code>{{ version.id }}</code>
        </dd>
        <dt class="text-sk-muted">{{ t('history.detail.parent') }}</dt>
        <dd>
          <RouterLink
            v-if="version.parent_id"
            :to="{ name: 'history-detail', params: { id: version.parent_id } }"
            class="text-sk-accent underline"
          >
            <code>{{ version.parent_id }}</code>
          </RouterLink>
          <template v-else>{{ t('history.detail.noParent') }}</template>
        </dd>
        <dt class="text-sk-muted">{{ t('history.detail.created') }}</dt>
        <dd>
          <time :datetime="version.created_at">{{ formatTime(version.created_at) }}</time>
        </dd>
        <dt class="text-sk-muted">{{ t('history.detail.author') }}</dt>
        <dd>{{ t('history.author', { type: version.author_type, id: version.author_id }) }}</dd>
        <dt class="text-sk-muted">{{ t('history.detail.source') }}</dt>
        <dd>{{ t(`history.source.${version.source}`) }}</dd>
        <dt class="text-sk-muted">{{ t('history.detail.schema') }}</dt>
        <dd>{{ version.schema_version }}</dd>
        <dt class="text-sk-muted">{{ t('history.detail.status') }}</dt>
        <dd class="flex flex-wrap items-center gap-2">
          <span class="inline-flex items-center gap-1">
            <i :class="['ti', version.applied ? 'ti-check' : 'ti-x']" aria-hidden="true" />
            {{ version.applied ? t('history.applied') : t('history.notApplied') }}
          </span>
          <span
            v-if="isCurrent"
            class="inline-flex items-center gap-1 rounded-full bg-sk-success-bg px-2 py-0.5 text-xs font-medium text-sk-success"
          >
            <i class="ti ti-circle-check" aria-hidden="true" />{{ t('history.current') }}
          </span>
        </dd>
      </dl>
    </section>

    <section aria-labelledby="diff-title">
      <h2 id="diff-title" class="mb-2 text-lg font-medium">{{ t('history.detail.diff') }}</h2>
      <DiffView :diff="version.diff" />
    </section>

    <section aria-labelledby="snap-title">
      <h2 id="snap-title" class="mb-2 text-lg font-medium">{{ t('history.detail.snapshot') }}</h2>
      <pre
        class="max-h-[32rem] overflow-auto rounded-sk-lg border border-sk-border bg-sk-surface-muted p-4 text-xs"
        tabindex="0"
        role="region"
        :aria-label="t('history.detail.snapshotLabel')"
        data-testid="snapshot"
        v-text="snapshotText"
      />
    </section>
  </div>

  <SkConfirmDialog
    v-model:open="confirmOpen"
    danger
    :busy="busy"
    :title="t('history.rollback.title', { id })"
    :message="t('history.rollback.message')"
    :confirm-label="t('history.rollback.confirm')"
    @confirm="rollback"
  >
    <p v-if="version" class="mt-2">
      {{ t('history.rollback.differences', version.snapshot.sites.length) }}
    </p>
  </SkConfirmDialog>
</template>
