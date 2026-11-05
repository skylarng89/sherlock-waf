<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useFormErrors } from '@/api/fieldErrors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkFormField from '@/components/SkFormField.vue'
import SkStatusBadge from '@/components/SkStatusBadge.vue'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import SwitchControl from '@/pages/sites/controls/SwitchControl.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import { clone } from '@/pages/sites/lib/json'
import { useWriteFlow } from '@/pages/sites/lib/useWriteFlow'
import WriteBanners from '@/pages/sites/WriteBanners.vue'
import { useToastStore } from '@/stores/toasts'
import {
  fromDraft,
  GEOIP_MANUAL_PATH,
  GEOIP_PROVIDERS,
  MAXMIND_IMPLEMENTED,
  REPUTATION_LISTS,
  toDraft,
  type FeedDraft,
} from './feeds'
import { absoluteTime, relativeTime } from './time'
import type { GlobalConfigStore } from './useGlobalConfig'

type FeedStatus = components['schemas']['FeedStatus']

const props = defineProps<{ store: GlobalConfigStore; canWrite: boolean }>()
const { t } = useI18n()
const { client, call } = useApi()
const toasts = useToastStore()

const draft = ref<FeedDraft>(toDraft(undefined))
const busy = ref(false)
const status = ref<FeedStatus[]>([])
const statusState = ref<'loading' | 'ready' | 'error'>('loading')

const form = useFormErrors({
  known: [
    'geoip.provider',
    'geoip.auto_update',
    'reputation_lists',
    'crowdsec.enabled',
    'crowdsec.lapi_url',
    'crowdsec.allow_private',
  ],
})
const flow = useWriteFlow({
  form,
  rebase: () => ({ prefixes: ['/global/feeds'], lists: ['reputation_lists'] }),
})

function sync() {
  draft.value = toDraft(props.store.config.value.global?.feeds)
}
watch(() => props.store.config.value, sync, { immediate: true })

async function loadStatus() {
  statusState.value = 'loading'
  try {
    status.value = (await call(client.GET('/feeds/status'), { toast: false })).data.items
    statusState.value = 'ready'
  } catch {
    status.value = []
    statusState.value = 'error'
  }
}
onMounted(loadStatus)

const warnings = computed(() =>
  status.value.filter((f) => f.state === 'stale' || f.state === 'failed'),
)

function toggleList(name: string, on: boolean) {
  const rest = draft.value.reputation_lists.filter((n) => n !== name)
  draft.value.reputation_lists = on ? [...rest, name] : rest
}

async function save() {
  flow.reset()
  busy.value = true
  try {
    const next = clone(draft.value)
    await props.store.save((cfg) => {
      cfg.global = { ...cfg.global, feeds: fromDraft(cfg.global?.feeds, next) }
    })
    toasts.success(t('access.feeds.saved'))
    void loadStatus()
  } catch (e) {
    flow.handle(e)
  } finally {
    busy.value = false
  }
}

async function reload() {
  flow.reset()
  await props.store.load()
}

function stateBadge(state: FeedStatus['state']) {
  switch (state) {
    case 'ok':
      return { state: 'ok' as const }
    case 'stale':
      return { state: 'warn' as const }
    case 'failed':
      return { state: 'error' as const }
    default:
      return { state: undefined }
  }
}
</script>

<template>
  <section class="flex flex-col gap-6" aria-labelledby="feeds-title">
    <div>
      <h2 id="feeds-title" class="text-lg font-semibold">{{ t('access.feeds.title') }}</h2>
      <p class="text-sk-muted">{{ t('access.feeds.description') }}</p>
    </div>

    <div
      v-for="f in warnings"
      :key="f.name"
      role="alert"
      class="rounded-sk border border-sk-warning bg-sk-warning-bg p-3 text-sk-warning"
      :data-testid="`feed-warning-${f.name}`"
    >
      <p class="font-medium">
        <i class="ti ti-alert-triangle" aria-hidden="true" />
        {{
          t(`access.feeds.warning.${f.state}`, { name: t(`access.feeds.names.${f.name}`, f.name) })
        }}
      </p>
      <p v-if="f.last_error">{{ t('access.feeds.lastError', { error: f.last_error }) }}</p>
      <p v-if="f.last_success">
        {{ t('access.feeds.lastSuccess', { when: absoluteTime(f.last_success) }) }}
      </p>
      <p>{{ t('access.feeds.keepsData') }}</p>
    </div>

    <div class="flex flex-col gap-2">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <h3 class="font-semibold">{{ t('access.feeds.statusTitle') }}</h3>
        <Button
          type="button"
          severity="secondary"
          icon="ti ti-refresh"
          :label="t('access.feeds.refresh')"
          :disabled="statusState === 'loading'"
          @click="loadStatus"
        />
      </div>
      <p v-if="statusState === 'loading'" role="status">{{ t('common.loading') }}…</p>
      <p v-else-if="statusState === 'error'" role="alert" class="text-sk-danger">
        <i class="ti ti-alert-circle" aria-hidden="true" />
        {{ t('access.feeds.statusFailed') }}
      </p>
      <p v-else-if="status.length === 0" class="text-sk-muted">
        {{ t('access.feeds.statusEmpty') }}
      </p>
      <div
        v-else
        class="overflow-x-auto"
        tabindex="0"
        role="region"
        :aria-label="t('access.feeds.scroll')"
      >
        <table class="w-full text-left" data-testid="feeds-status">
          <caption class="sr-only">
            {{
              t('access.feeds.caption')
            }}
          </caption>
          <thead>
            <tr class="border-b border-sk-border-strong">
              <th scope="col" class="p-2">{{ t('access.feeds.cols.feed') }}</th>
              <th scope="col" class="p-2">{{ t('access.feeds.cols.state') }}</th>
              <th scope="col" class="p-2">{{ t('access.feeds.cols.entries') }}</th>
              <th scope="col" class="p-2">{{ t('access.feeds.cols.lastSuccess') }}</th>
              <th scope="col" class="p-2">{{ t('access.feeds.cols.lastError') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="f in status" :key="f.name" class="border-b border-sk-border">
              <th scope="row" class="p-2 font-normal">
                {{ t(`access.feeds.names.${f.name}`, f.name) }}
              </th>
              <td class="p-2">
                <SkStatusBadge
                  v-if="stateBadge(f.state).state"
                  :state="stateBadge(f.state).state"
                  :label="t(`access.feeds.states.${f.state}`)"
                />
                <SkStatusBadge v-else mode="off" :label="t(`access.feeds.states.${f.state}`)" />
              </td>
              <td class="p-2">{{ f.entries ?? '-' }}</td>
              <td class="p-2">
                <template v-if="f.last_success">
                  {{ relativeTime(f.last_success) }}
                  <span class="block text-sm text-sk-muted">{{
                    absoluteTime(f.last_success)
                  }}</span>
                </template>
                <template v-else>-</template>
              </td>
              <td class="p-2">{{ f.last_error || '-' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <form class="flex flex-col gap-4" novalidate data-testid="feeds-form" @submit.prevent="save">
      <h3 class="font-semibold">{{ t('access.feeds.settingsTitle') }}</h3>
      <WriteBanners
        :stale="flow.stale.value"
        :precondition="flow.precondition.value"
        :unmatched="form.unmatched.value"
        @reload="reload"
      />
      <fieldset class="flex flex-col gap-3" :disabled="!canWrite">
        <legend class="mb-1 font-medium">{{ t('access.feeds.geoip.title') }}</legend>
        <SkFormField
          :label="t('access.feeds.geoip.provider')"
          :help="t('access.feeds.geoip.providerHelp')"
          :error="form.errorFor('geoip.provider')"
        >
          <template #default="{ attrs, invalid }">
            <SelectControl
              v-bind="attrs"
              v-model="draft.geoip.provider"
              :options="
                GEOIP_PROVIDERS.map((p) => ({
                  value: p,
                  label: t(`access.feeds.geoip.providers.${p}`),
                }))
              "
              :aria-invalid="invalid ? 'true' : undefined"
            />
          </template>
        </SkFormField>
        <p
          v-if="draft.geoip.provider === 'maxmind' && !MAXMIND_IMPLEMENTED"
          role="status"
          class="rounded-sk border border-sk-warning bg-sk-warning-bg p-2 text-sm text-sk-warning"
        >
          <i class="ti ti-alert-triangle" aria-hidden="true" />
          {{ t('access.feeds.geoip.maxmindMissing') }}
        </p>
        <SkFormField
          :label="t('access.feeds.geoip.autoUpdate')"
          :error="form.errorFor('geoip.auto_update')"
        >
          <template #default="{ attrs }">
            <SwitchControl
              v-bind="attrs"
              v-model="draft.geoip.auto_update"
              :label="t('access.feeds.geoip.autoUpdateSwitch')"
            />
          </template>
        </SkFormField>
        <div class="rounded-sk border border-sk-border bg-sk-surface-muted p-3 text-sm">
          <p class="font-medium">
            <i class="ti ti-upload" aria-hidden="true" />
            {{ t('access.feeds.geoip.manualTitle') }}
          </p>
          <p>{{ t('access.feeds.geoip.manualBody') }}</p>
          <p class="mt-1 font-mono">&lt;data-dir&gt;/{{ GEOIP_MANUAL_PATH }}</p>
          <p class="mt-1 text-sk-muted">{{ t('access.feeds.geoip.noUploadApi') }}</p>
        </div>
      </fieldset>

      <fieldset class="flex flex-col gap-2" :disabled="!canWrite">
        <legend class="mb-1 font-medium">{{ t('access.feeds.reputation.title') }}</legend>
        <p class="text-sm text-sk-muted">{{ t('access.feeds.reputation.help') }}</p>
        <label v-for="name in REPUTATION_LISTS" :key="name" class="flex items-center gap-2">
          <input
            type="checkbox"
            class="size-4 accent-[var(--sk-accent)]"
            :checked="draft.reputation_lists.includes(name)"
            @change="toggleList(name, ($event.target as HTMLInputElement).checked)"
          />
          {{ t(`access.feeds.names.${name}`) }}
        </label>
        <p v-if="form.errorFor('reputation_lists')" role="alert" class="text-sm text-sk-danger">
          {{ form.errorFor('reputation_lists') }}
        </p>
      </fieldset>

      <fieldset class="flex flex-col gap-3" :disabled="!canWrite">
        <legend class="mb-1 font-medium">{{ t('access.feeds.crowdsec.title') }}</legend>
        <SkFormField
          :label="t('access.feeds.crowdsec.enabled')"
          :error="form.errorFor('crowdsec.enabled')"
        >
          <template #default="{ attrs }">
            <SwitchControl
              v-bind="attrs"
              v-model="draft.crowdsec.enabled"
              :label="t('access.feeds.crowdsec.enabledSwitch')"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('access.feeds.crowdsec.url')"
          :help="t('access.feeds.crowdsec.urlHelp')"
          :error="form.errorFor('crowdsec.lapi_url')"
        >
          <template #default="{ attrs, invalid }">
            <TextControl
              v-bind="attrs"
              v-model="draft.crowdsec.lapi_url"
              mono
              :aria-invalid="invalid ? 'true' : undefined"
              @update:model-value="form.clear('crowdsec.lapi_url')"
            />
          </template>
        </SkFormField>
        <SkFormField
          :label="t('access.feeds.crowdsec.allowPrivate')"
          :help="t('access.feeds.crowdsec.allowPrivateHelp')"
          :error="form.errorFor('crowdsec.allow_private')"
        >
          <template #default="{ attrs }">
            <SwitchControl
              v-bind="attrs"
              v-model="draft.crowdsec.allow_private"
              :label="t('access.feeds.crowdsec.allowPrivateSwitch')"
            />
          </template>
        </SkFormField>
      </fieldset>

      <p class="rounded-sk border border-sk-border bg-sk-surface-muted p-3 text-sm">
        <i class="ti ti-key" aria-hidden="true" />
        {{ t('access.feeds.secretsNote') }}
      </p>

      <div v-if="canWrite">
        <Button type="submit" :label="t('access.feeds.save')" :loading="busy" :disabled="busy" />
      </div>
    </form>
  </section>
</template>
