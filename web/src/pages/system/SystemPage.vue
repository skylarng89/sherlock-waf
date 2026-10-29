<script setup lang="ts">
import Button from 'openvue/button'
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkPageHeader from '@/components/SkPageHeader.vue'
import SkStatusBadge from '@/components/SkStatusBadge.vue'
import { absoluteTime } from '@/pages/access/time'

type Info = components['schemas']['SystemInfo']
type Status = components['schemas']['SystemStatus']
type Feed = components['schemas']['FeedStatus']

const { t, n } = useI18n()
const { client, call } = useApi()

const info = ref<Info>()
const status = ref<Status>()
const feeds = ref<Feed[]>()
const loading = ref(true)
const failed = ref(false)

async function load() {
  loading.value = true
  const results = await Promise.allSettled([
    call(client.GET('/system/info'), { toast: false }).then((r) => (info.value = r.data)),
    call(client.GET('/system/status'), { toast: false }).then((r) => (status.value = r.data)),
    call(client.GET('/feeds/status'), { toast: false }).then((r) => (feeds.value = r.data.items)),
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
