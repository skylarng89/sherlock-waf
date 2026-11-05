<script setup lang="ts">
import Button from 'openvue/button'
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkPageHeader from '@/components/SkPageHeader.vue'
import SkStatusBadge from '@/components/SkStatusBadge.vue'
import { absoluteTime } from '@/pages/access/time'

type Info = components['schemas']['SystemInfo']
type Status = components['schemas']['SystemStatus']
type Feed = components['schemas']['FeedStatus']
type UpdateStatus = components['schemas']['UpdateStatus']
type ApplyResult = components['schemas']['UpdateApplyResult']
type Backup = components['schemas']['Backup']

/** Why the update section has nothing to show: 501 = not supported here, 502 = release server unreachable. */
type UpdateProblem = 'unsupported' | 'unreachable' | 'error'

const { t, n } = useI18n()
const { client, call } = useApi()
const session = useSessionStore()
const toasts = useToastStore()

const info = ref<Info>()
const status = ref<Status>()
const feeds = ref<Feed[]>()
const update = ref<UpdateStatus>()
const updateProblem = ref<UpdateProblem>()
const backups = ref<Backup[]>()
const backupsFailed = ref(false)
const applyOpen = ref(false)
const applying = ref(false)
const applyResult = ref<ApplyResult>()
const applyError = ref('')
const loading = ref(true)
const failed = ref(false)

function updateProblemOf(e: unknown): UpdateProblem {
  if (!isApiError(e)) throw e
  return e.status === 501 ? 'unsupported' : e.status === 502 ? 'unreachable' : 'error'
}

// On demand, not on page load: the check contacts the release server and a node that cannot
// update answers 501, which the browser would log as a console error on every visit.
const checking = ref(false)
async function loadUpdate() {
  checking.value = true
  applyResult.value = undefined
  applyError.value = ''
  update.value = undefined
  updateProblem.value = undefined
  try {
    update.value = (await call(client.GET('/system/update'), { toast: false })).data
  } catch (e) {
    updateProblem.value = updateProblemOf(e)
  } finally {
    checking.value = false
  }
}

async function loadBackups() {
  backupsFailed.value = false
  try {
    backups.value = (await call(client.GET('/system/backups'), { toast: false })).data.items
  } catch (e) {
    if (!isApiError(e)) throw e
    backups.value = undefined
    backupsFailed.value = true
  }
}

async function apply() {
  applying.value = true
  applyError.value = ''
  try {
    applyResult.value = (await call(client.POST('/system/update/apply'), { toast: false })).data
    applyOpen.value = false
    toasts.success(t('system.update.staged'))
  } catch (e) {
    if (!isApiError(e)) throw e
    applyOpen.value = false
    applyError.value = e.detail || e.title
  } finally {
    applying.value = false
  }
}

async function load() {
  loading.value = true
  const results = await Promise.allSettled([
    call(client.GET('/system/info'), { toast: false }).then((r) => (info.value = r.data)),
    call(client.GET('/system/status'), { toast: false }).then((r) => (status.value = r.data)),
    call(client.GET('/feeds/status'), { toast: false }).then((r) => (feeds.value = r.data.items)),
    loadBackups(),
  ])
  failed.value = results.some((r) => r.status === 'rejected')
  for (const r of results) if (r.status === 'rejected' && !isApiError(r.reason)) throw r.reason
  loading.value = false
}
onMounted(load)

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
function bytes(value: number): string {
  let v = value
  let i = 0
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024
    i++
  }
  return `${n(i === 0 ? v : Math.round(v * 10) / 10)} ${UNITS[i]}`
}

const feedState = (s: Feed['state']): 'ok' | 'warn' | 'error' =>
  s === 'ok' ? 'ok' : s === 'failed' ? 'error' : 'warn'
</script>

<template>
  <SkPageHeader :title="t('system.title')" :description="t('system.description')">
    <template #actions>
      <Button
        type="button"
        severity="secondary"
        icon="ti ti-refresh"
        :label="t('system.refresh')"
        @click="load"
      />
    </template>
  </SkPageHeader>

  <p v-if="loading" role="status" class="text-sk-muted">{{ t('system.loading') }}…</p>
  <p v-if="failed" role="alert" class="mb-4 text-sk-danger">{{ t('system.loadError') }}</p>

  <div class="mb-6 grid gap-4 lg:grid-cols-2">
    <section
      v-if="info"
      aria-labelledby="sys-version"
      class="rounded-sk-lg border border-sk-border bg-sk-surface p-4"
    >
      <h2 id="sys-version" class="mb-2 text-lg font-semibold">{{ t('system.version.title') }}</h2>
      <dl class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1">
        <dt class="text-sk-muted">{{ t('system.version.ready') }}</dt>
        <dd>
          <SkStatusBadge
            :state="info.ready ? 'ok' : 'error'"
            :label="info.ready ? t('system.version.readyYes') : t('system.version.readyNo')"
          />
        </dd>
        <dt class="text-sk-muted">{{ t('system.version.version') }}</dt>
        <dd data-testid="sys-version">{{ info.version }}</dd>
        <dt class="text-sk-muted">{{ t('system.version.commit') }}</dt>
        <dd class="font-mono text-sm">{{ info.commit || t('system.version.unknown') }}</dd>
        <dt class="text-sk-muted">{{ t('system.version.crs') }}</dt>
        <dd data-testid="sys-crs">{{ info.crs_version }}</dd>
        <dt class="text-sk-muted">{{ t('system.version.database') }}</dt>
        <dd>{{ info.database }}</dd>
        <dt class="text-sk-muted">{{ t('system.version.configVersion') }}</dt>
        <dd class="font-mono text-sm">{{ info.config_version || t('system.version.unknown') }}</dd>
        <dt class="text-sk-muted">{{ t('system.version.features') }}</dt>
        <dd>
          {{ info.features.length ? info.features.join(', ') : t('system.version.noFeatures') }}
        </dd>
        <template v-if="info.audit_head">
          <dt class="text-sk-muted">{{ t('system.version.auditHead') }}</dt>
          <dd class="break-all font-mono text-sm">
            {{
              t('system.version.auditHeadValue', {
                seq: info.audit_head.seq ?? '',
                hash: info.audit_head.hash ?? '',
              })
            }}
          </dd>
        </template>
      </dl>
    </section>

    <section
      v-if="status"
      aria-labelledby="sys-storage"
      class="rounded-sk-lg border border-sk-border bg-sk-surface p-4"
    >
      <h2 id="sys-storage" class="mb-2 text-lg font-semibold">{{ t('system.storage.title') }}</h2>
      <dl class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1">
        <dt class="text-sk-muted">{{ t('system.storage.stored') }}</dt>
        <dd data-testid="sys-stored">{{ n(status.events_stored) }}</dd>
        <dt class="text-sk-muted">{{ t('system.storage.published') }}</dt>
        <dd>{{ n(status.events_published) }}</dd>
        <dt class="text-sk-muted">{{ t('system.storage.dropped') }}</dt>
        <dd>
          <span data-testid="sys-dropped">{{ n(status.events_dropped) }}</span>
          <SkStatusBadge
            class="ml-2"
            :state="status.events_dropped > 0 ? 'warn' : 'ok'"
            :label="
              status.events_dropped > 0
                ? t('common.status.state.warn')
                : t('system.storage.droppedOk')
            "
          />
        </dd>
        <dt class="text-sk-muted">{{ t('system.storage.disk') }}</dt>
        <dd data-testid="sys-disk">
          {{ status.data_dir_truncated ? '≥ ' : '' }}{{ bytes(status.data_dir_bytes) }}
        </dd>
        <dt class="text-sk-muted">{{ t('system.storage.retention') }}</dt>
        <dd>
          {{
            status.retention_days
              ? t('system.storage.retentionDays', { days: status.retention_days })
              : t('system.storage.retentionUnknown')
          }}
        </dd>
      </dl>
      <p v-if="status.events_dropped > 0" class="mt-2 text-sk-warning">
        <i class="ti ti-alert-triangle" aria-hidden="true" /> {{ t('system.storage.droppedWarn') }}
      </p>
      <p v-if="status.data_dir_truncated" class="mt-2 text-sm text-sk-muted">
        <i class="ti ti-info-circle" aria-hidden="true" /> {{ t('system.storage.diskTruncated') }}
      </p>
    </section>
  </div>

  <section
    aria-labelledby="sys-update"
    class="mb-6 rounded-sk-lg border border-sk-border bg-sk-surface p-4"
    data-testid="update-section"
  >
    <h2 id="sys-update" class="mb-2 text-lg font-semibold">{{ t('system.update.title') }}</h2>
    <Button
      v-if="!update && !updateProblem"
      type="button"
      severity="secondary"
      icon="ti ti-cloud-search"
      :label="t('system.update.check')"
      :loading="checking"
      :disabled="checking"
      data-testid="update-check"
      @click="loadUpdate"
    />
    <p v-if="updateProblem" data-testid="update-problem" class="text-sk-muted">
      {{ t(`system.update.problem.${updateProblem}`) }}
    </p>
    <template v-else-if="update">
      <p v-if="update.in_container" class="mb-2" data-testid="update-container">
        <i class="ti ti-info-circle" aria-hidden="true" /> {{ t('system.update.inContainer') }}
      </p>
      <dl class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1">
        <dt class="text-sk-muted">{{ t('system.update.current') }}</dt>
        <dd>{{ update.current }}</dd>
        <dt class="text-sk-muted">{{ t('system.update.latest') }}</dt>
        <dd>
          {{ update.latest }}
          <SkStatusBadge
            class="ml-2"
            :state="update.available ? 'warn' : 'ok'"
            :label="update.available ? t('system.update.available') : t('system.update.upToDate')"
          />
        </dd>
        <template v-if="update.crs_version">
          <dt class="text-sk-muted">{{ t('system.update.crs') }}</dt>
          <dd>{{ update.crs_version }}</dd>
        </template>
        <template v-if="update.staged_version">
          <dt class="text-sk-muted">{{ t('system.update.stagedVersion') }}</dt>
          <dd data-testid="update-staged">{{ update.staged_version }}</dd>
        </template>
      </dl>
      <p v-if="update.staged_version" class="mt-2 text-sk-warning">
        <i class="ti ti-alert-triangle" aria-hidden="true" /> {{ t('system.update.restartNote') }}
      </p>
      <p v-if="update.available && update.reason" class="mt-2 text-sk-warning">
        {{ t('system.update.reason', { reason: update.reason }) }}
      </p>
      <p
        v-if="update.available && !update.reason && !update.in_container"
        class="mt-2 text-sm text-sk-muted"
      >
        {{ t('system.update.stageExplain') }}
      </p>
      <Button
        v-if="
          update.available && !update.reason && !update.in_container && session.can('system:update')
        "
        class="mt-3"
        type="button"
        icon="ti ti-download"
        :label="t('system.update.apply')"
        data-testid="update-apply"
        @click="applyOpen = true"
      />
    </template>
    <p v-if="applyResult" role="status" class="mt-3" data-testid="update-result">
      {{
        t(`system.update.result.${applyResult.state}`, {
          from: applyResult.from,
          to: applyResult.to,
        })
      }}
      {{ applyResult.restart }}
    </p>
    <p v-if="applyError" role="alert" class="mt-3 text-sk-danger" data-testid="update-error">
      {{ t('system.update.applyFailed', { detail: applyError }) }}
    </p>
  </section>

  <SkConfirmDialog
    v-model:open="applyOpen"
    :title="t('system.update.confirmTitle')"
    :message="t('system.update.confirmBody', { version: update?.latest ?? '' })"
    :confirm-label="t('system.update.apply')"
    :busy="applying"
    @confirm="apply"
  />

  <section aria-labelledby="sys-backups" class="mb-6">
    <h2 id="sys-backups" class="mb-2 text-lg font-semibold">{{ t('system.backups.title') }}</h2>
    <p v-if="backupsFailed" data-testid="backups-problem" class="text-sk-muted">
      {{ t('system.backups.error') }}
    </p>
    <p v-else-if="backups && !backups.length" class="text-sk-muted">
      {{ t('system.backups.none') }}
    </p>
    <div
      v-else-if="backups"
      class="overflow-x-auto"
      tabindex="0"
      role="region"
      :aria-label="t('system.backups.scroll')"
    >
      <table class="w-full text-left" data-testid="backups-table">
        <caption class="sr-only">
          {{
            t('system.backups.caption')
          }}
        </caption>
        <thead>
          <tr class="border-b border-sk-border-strong">
            <th scope="col" class="p-2">{{ t('system.backups.name') }}</th>
            <th scope="col" class="p-2">{{ t('system.backups.created') }}</th>
            <th scope="col" class="p-2">{{ t('system.backups.size') }}</th>
            <th scope="col" class="p-2">{{ t('system.backups.encrypted') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="b in backups" :key="b.name" class="border-b border-sk-border">
            <th scope="row" class="break-all p-2 font-mono font-normal">{{ b.name }}</th>
            <td class="p-2">
              <time :datetime="b.created_at">{{ absoluteTime(b.created_at) }}</time>
            </td>
            <td class="p-2">{{ bytes(b.bytes) }}</td>
            <td class="p-2">
              {{ b.encrypted ? t('system.backups.yes') : t('system.backups.no') }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>

  <section v-if="feeds" aria-labelledby="sys-feeds">
    <h2 id="sys-feeds" class="mb-2 text-lg font-semibold">{{ t('system.feeds.title') }}</h2>
    <p v-if="!feeds.length" class="text-sk-muted">{{ t('system.feeds.none') }}</p>
    <div
      v-else
      class="overflow-x-auto"
      tabindex="0"
      role="region"
      :aria-label="t('system.feeds.scroll')"
    >
      <table class="w-full text-left" data-testid="feeds-table">
        <caption class="sr-only">
          {{
            t('system.feeds.caption')
          }}
        </caption>
        <thead>
          <tr class="border-b border-sk-border-strong">
            <th scope="col" class="p-2">{{ t('system.feeds.name') }}</th>
            <th scope="col" class="p-2">{{ t('system.feeds.state') }}</th>
            <th scope="col" class="p-2">{{ t('system.feeds.lastSuccess') }}</th>
            <th scope="col" class="p-2">{{ t('system.feeds.entries') }}</th>
            <th scope="col" class="p-2">{{ t('system.feeds.error') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="f in feeds" :key="f.name" class="border-b border-sk-border">
            <th scope="row" class="p-2 font-mono font-normal">{{ f.name }}</th>
            <td class="p-2">
              <SkStatusBadge
                :state="feedState(f.state)"
                :label="t(`system.feeds.states.${f.state}`)"
              />
            </td>
            <td class="p-2">
              <time v-if="f.last_success" :datetime="f.last_success">{{
                absoluteTime(f.last_success)
              }}</time>
              <template v-else>{{ t('system.feeds.never') }}</template>
            </td>
            <td class="p-2">{{ f.entries === undefined ? '' : n(f.entries) }}</td>
            <td class="break-all p-2 text-sm">{{ f.last_error }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
