<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { RouterLink } from 'vue-router'
import { isApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkFormDialog from '@/components/SkFormDialog.vue'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { relativeTime } from '@/pages/access/time'
import NumberControl from '@/pages/sites/controls/NumberControl.vue'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import SwitchControl from '@/pages/sites/controls/SwitchControl.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import SettingsFields from './SettingsFields.vue'
import {
  ALERT_KINDS,
  ALERT_PARAM_SPECS,
  COOLDOWN_DEFAULT,
  COOLDOWN_MAX,
  COOLDOWN_MIN,
  ID_PATTERN,
  defaultsFor,
  modelFromSettings,
  settingsFromModel,
  slugify,
  type Model,
} from './spec'

type Rule = components['schemas']['AlertRule']
type Status = components['schemas']['AlertStatus']
type Kind = Rule['kind']
type Severity = Rule['severity']

const REFRESH_MS = 15_000
const SEVERITIES: Severity[] = ['info', 'warning', 'critical']

const { t } = useI18n()
const session = useSessionStore()
const toasts = useToastStore()
const { client, call } = useApi()
const canWrite = computed(() => session.can('config:write'))

const rules = ref<Rule[]>([])
const statuses = ref<Record<string, Status>>({})
const channels = ref<components['schemas']['NotificationChannel'][]>([])
const sites = ref<string[]>([])
const state = ref<'loading' | 'ready' | 'error'>('loading')
const now = ref(Date.now())
const announcement = ref('')
const pageError = ref('')
let timer: ReturnType<typeof setInterval> | undefined

const channelNames = computed(() => Object.fromEntries(channels.value.map((c) => [c.id, c.name])))

async function loadStatus() {
  try {
    const res = await call(client.GET('/alerts/status'), { toast: false })
    statuses.value = Object.fromEntries(res.data.items.map((s) => [s.rule_id, s]))
  } catch {
    // Live state is advisory; the stored rules still show.
  }
  now.value = Date.now()
}

async function load(silent = false) {
  if (!silent) state.value = 'loading'
  try {
    rules.value = (await call(client.GET('/alert-rules'), { toast: false })).data.items
    state.value = 'ready'
  } catch {
    if (!silent || state.value !== 'ready') state.value = 'error'
  }
  await loadStatus()
}

async function loadLookups() {
  try {
    channels.value = (await call(client.GET('/notification-channels'), { toast: false })).data.items
  } catch {
    channels.value = []
  }
  try {
    sites.value = (await call(client.GET('/sites'), { toast: false })).data.items.map((s) => s.id)
  } catch {
    sites.value = []
  }
}

function tick() {
  if (!document.hidden && !dialogOpen.value) void load(true)
}

onMounted(() => {
  void load()
  void loadLookups()
  timer = setInterval(tick, REFRESH_MS)
  document.addEventListener('visibilitychange', tick)
})
onBeforeUnmount(() => {
  if (timer !== undefined) clearInterval(timer)
  document.removeEventListener('visibilitychange', tick)
})

// --- dialog ---

const dialogOpen = ref(false)
const editing = ref<Rule>()
const form = ref({
  id: '',
  name: '',
  kind: 'blocks_threshold' as Kind,
  severity: 'warning' as Severity,
  cooldown: COOLDOWN_DEFAULT as number | undefined,
  channelIds: [] as string[],
  enabled: true,
})
const idTouched = ref(false)
const model = ref<Model>({})
const busy = ref(false)
const formError = ref('')
const fieldErrors = ref<Record<string, string>>({})

const spec = computed(() => ALERT_PARAM_SPECS[form.value.kind] ?? [])
const kindOptions = ALERT_KINDS.map((k) => ({
  value: k,
  label: t(`integrations.options.alertKind.${k}`),
}))
const severityOptions = SEVERITIES.map((s) => ({
  value: s,
  label: t(`integrations.options.severity.${s}`),
}))

function resetModel(kind: Kind, params?: Record<string, unknown>) {
  const s = ALERT_PARAM_SPECS[kind] ?? []
  model.value = params ? modelFromSettings(s, params) : defaultsFor(s)
}

function openCreate() {
  editing.value = undefined
  form.value = {
    id: '',
    name: '',
    kind: 'blocks_threshold',
    severity: 'warning',
    cooldown: COOLDOWN_DEFAULT,
    channelIds: [],
    enabled: true,
  }
  idTouched.value = false
  resetModel('blocks_threshold')
  formError.value = ''
  fieldErrors.value = {}
  dialogOpen.value = true
}

function openEdit(r: Rule) {
  editing.value = r
  form.value = {
    id: r.id,
    name: r.name,
    kind: r.kind,
    severity: r.severity,
    cooldown: r.cooldown_seconds,
    channelIds: [...r.channel_ids],
    enabled: r.enabled,
  }
  resetModel(r.kind, r.params)
  formError.value = ''
  fieldErrors.value = {}
  dialogOpen.value = true
}

function onKindChange(kind: Kind | undefined) {
  if (!kind) return
  form.value.kind = kind
  resetModel(kind, editing.value?.kind === kind ? editing.value.params : undefined)
}

function onNameInput(name: string) {
  form.value.name = name
  if (!idTouched.value && !editing.value) form.value.id = slugify(name)
}

function toggleChannel(id: string, on: boolean) {
  const set = new Set(form.value.channelIds)
  if (on) set.add(id)
  else set.delete(id)
  form.value.channelIds = [...set]
}

function problemText(e: unknown): string {
  return isApiError(e) ? (e.detail ?? e.title) : t('integrations.errors.generic')
}

function body() {
  const base = editing.value?.kind === form.value.kind ? editing.value.params : undefined
  return {
    name: form.value.name.trim(),
    kind: form.value.kind,
    enabled: form.value.enabled,
    severity: form.value.severity,
    cooldown_seconds: form.value.cooldown ?? COOLDOWN_DEFAULT,
    channel_ids: form.value.channelIds,
    params: settingsFromModel(spec.value, model.value, base).settings,
  }
}

async function save() {
  formError.value = ''
  const errors: Record<string, string> = {}
  if (form.value.name.trim() === '') errors.name = t('integrations.errors.nameRequired')
  if (!editing.value && !ID_PATTERN.test(form.value.id)) errors.id = t('integrations.errors.id')
  const c = form.value.cooldown
  if (c === undefined || c < COOLDOWN_MIN || c > COOLDOWN_MAX) {
    errors.cooldown = t('integrations.errors.cooldown', { min: COOLDOWN_MIN, max: COOLDOWN_MAX })
  }
  fieldErrors.value = errors
  if (Object.keys(errors).length > 0) return

  busy.value = true
  try {
    await call(
      client.PUT('/alert-rules/{id}', { params: { path: { id: form.value.id } }, body: body() }),
      { toast: false },
    )
    dialogOpen.value = false
    announcement.value = t('integrations.alerts.saved', { name: form.value.name })
    toasts.success(announcement.value)
    await load(true)
  } catch (e) {
    formError.value = problemText(e)
  } finally {
    busy.value = false
  }
}

async function toggle(r: Rule, enabled: boolean) {
  pageError.value = ''
  try {
    await call(
      client.PUT('/alert-rules/{id}', {
        params: { path: { id: r.id } },
        body: {
          name: r.name,
          kind: r.kind,
          enabled,
          severity: r.severity,
          cooldown_seconds: r.cooldown_seconds,
          channel_ids: r.channel_ids,
          params: r.params,
        },
      }),
      { toast: false },
    )
    announcement.value = t(enabled ? 'integrations.enabledNamed' : 'integrations.disabledNamed', {
      name: r.name,
    })
  } catch (e) {
    pageError.value = problemText(e)
  }
  await load(true)
}

const toDelete = ref<Rule>()
const deleting = ref(false)

async function remove() {
  const r = toDelete.value
  if (!r) return
  deleting.value = true
  pageError.value = ''
  try {
    await call(client.DELETE('/alert-rules/{id}', { params: { path: { id: r.id } } }), {
      toast: false,
    })
    announcement.value = t('integrations.alerts.deleted', { name: r.name })
    toasts.success(announcement.value)
  } catch (e) {
    pageError.value = problemText(e)
  } finally {
    toDelete.value = undefined
    deleting.value = false
  }
  await load(true)
}

function duration(seconds: number): string {
  if (seconds % 86_400 === 0) return t('integrations.duration.days', { n: seconds / 86_400 })
  if (seconds % 3_600 === 0) return t('integrations.duration.hours', { n: seconds / 3_600 })
  if (seconds % 60 === 0) return t('integrations.duration.minutes', { n: seconds / 60 })
  return t('integrations.duration.seconds', { n: seconds })
}
</script>

<template>
  <SkPageHeader
    :title="t('integrations.alerts.title')"
    :description="t('integrations.alerts.description')"
  >
    <template #actions>
      <Button
        v-if="canWrite"
        type="button"
        icon="ti ti-plus"
        :label="t('integrations.alerts.add')"
        data-testid="alert-add"
        @click="openCreate"
      />
    </template>
  </SkPageHeader>

  <p v-if="!canWrite" role="status" class="mb-4 text-sk-muted">
    <i class="ti ti-lock" aria-hidden="true" />
    {{ t('integrations.readOnly') }}
  </p>
  <p class="sr-only" aria-live="polite">{{ announcement }}</p>
  <p
    v-if="pageError"
    role="alert"
    class="mb-4 rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
  >
    <i class="ti ti-alert-circle" aria-hidden="true" />
    {{ pageError }}
  </p>

  <p v-if="state === 'loading'" role="status">{{ t('common.loading') }}…</p>
  <div
    v-else-if="state === 'error'"
    role="alert"
    class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
  >
    <p>
      <i class="ti ti-alert-circle" aria-hidden="true" />
      {{ t('integrations.alerts.loadFailed') }}
    </p>
    <Button :label="t('common.actions.retry')" severity="secondary" @click="load()" />
  </div>
  <SkEmptyState
    v-else-if="rules.length === 0"
    icon="ti ti-bell-ringing"
    :title="t('integrations.alerts.emptyTitle')"
    :description="t('integrations.alerts.emptyDescription')"
  />
  <div
    v-else
    class="overflow-x-auto"
    tabindex="0"
    role="region"
    :aria-label="t('integrations.alerts.scroll')"
  >
    <table class="w-full text-left" data-testid="alerts-table">
      <caption class="sr-only">
        {{
          t('integrations.alerts.caption')
        }}
      </caption>
      <thead>
        <tr class="border-b border-sk-border-strong">
          <th scope="col" class="p-2">{{ t('integrations.cols.name') }}</th>
          <th scope="col" class="p-2">{{ t('integrations.cols.kind') }}</th>
          <th scope="col" class="p-2">{{ t('integrations.cols.severity') }}</th>
          <th scope="col" class="p-2">{{ t('integrations.cols.cooldown') }}</th>
          <th scope="col" class="p-2">{{ t('integrations.cols.channels') }}</th>
          <th scope="col" class="p-2">{{ t('integrations.cols.enabled') }}</th>
          <th scope="col" class="p-2">{{ t('integrations.cols.state') }}</th>
          <th v-if="canWrite" scope="col" class="p-2">{{ t('integrations.cols.actions') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="r in rules"
          :key="r.id"
          class="border-b border-sk-border align-top"
          :data-testid="`alert-${r.id}`"
        >
          <th scope="row" class="p-2 font-medium">{{ r.name }}</th>
          <td class="p-2">{{ t(`integrations.options.alertKind.${r.kind}`) }}</td>
          <td class="p-2">{{ t(`integrations.options.severity.${r.severity}`) }}</td>
          <td class="p-2">{{ duration(r.cooldown_seconds) }}</td>
          <td class="p-2">
            <template v-if="r.channel_ids.length">
              {{ r.channel_ids.map((id) => channelNames[id] ?? id).join(', ') }}
            </template>
            <span v-else class="text-sk-muted">{{ t('common.none') }}</span>
          </td>
          <td class="p-2">
            <SwitchControl
              v-if="canWrite"
              :model-value="r.enabled"
              :label="t('integrations.enabledNamed', { name: r.name })"
              @update:model-value="toggle(r, $event)"
            />
            <span v-else>{{ r.enabled ? t('common.yes') : t('common.no') }}</span>
          </td>
          <td class="p-2 text-sm">
            <template v-if="r.enabled && statuses[r.id]">
              <p
                v-if="statuses[r.id]!.firing"
                class="inline-flex items-center gap-1 font-medium text-sk-danger"
                data-testid="firing"
              >
                <i class="ti ti-flame" aria-hidden="true" />
                {{ t('integrations.alerts.firing') }}
              </p>
              <p v-else class="inline-flex items-center gap-1 text-sk-success">
                <i class="ti ti-circle-check" aria-hidden="true" />
                {{ t('integrations.alerts.ok') }}
              </p>
              <dl class="mt-1 grid grid-cols-[auto_1fr] gap-x-2">
                <dt class="text-sk-muted">{{ t('integrations.alerts.lastEvaluated') }}</dt>
                <dd>
                  <time
                    v-if="statuses[r.id]!.last_evaluated"
                    :datetime="statuses[r.id]!.last_evaluated!"
                  >
                    {{ relativeTime(statuses[r.id]!.last_evaluated!, now) }}
                  </time>
                  <template v-else>{{ t('integrations.never') }}</template>
                </dd>
                <dt class="text-sk-muted">{{ t('integrations.alerts.lastFired') }}</dt>
                <dd>
                  <time v-if="statuses[r.id]!.last_fired" :datetime="statuses[r.id]!.last_fired!">
                    {{ relativeTime(statuses[r.id]!.last_fired!, now) }}
                  </time>
                  <template v-else>{{ t('integrations.never') }}</template>
                </dd>
                <dt class="text-sk-muted">{{ t('integrations.alerts.suppressed') }}</dt>
                <dd>{{ statuses[r.id]!.suppressed }}</dd>
              </dl>
              <p v-if="statuses[r.id]!.last_error" class="mt-1 text-sk-danger">
                <i class="ti ti-alert-triangle" aria-hidden="true" />
                {{ statuses[r.id]!.last_error }}
              </p>
            </template>
            <span v-else class="text-sk-muted">{{ t('integrations.alerts.notEvaluating') }}</span>
          </td>
          <td v-if="canWrite" class="p-2">
            <div class="flex flex-wrap gap-2">
              <button
                type="button"
                class="rounded-sk border border-sk-border-strong px-2 py-1"
                :aria-label="t('integrations.editNamed', { name: r.name })"
                @click="openEdit(r)"
              >
                <i class="ti ti-pencil" aria-hidden="true" />
                {{ t('common.actions.edit') }}
              </button>
              <button
                type="button"
                class="rounded-sk border border-sk-border-strong px-2 py-1"
                :aria-label="t('integrations.deleteNamed', { name: r.name })"
                @click="toDelete = r"
              >
                <i class="ti ti-trash" aria-hidden="true" />
                {{ t('common.actions.delete') }}
              </button>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <SkFormDialog
    v-if="canWrite"
    v-model:open="dialogOpen"
    :title="editing ? t('integrations.alerts.editTitle') : t('integrations.alerts.addTitle')"
    :busy="busy"
    @submit="save"
  >
    <p
      v-if="formError"
      role="alert"
      class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
      data-testid="form-error"
    >
      <i class="ti ti-alert-circle" aria-hidden="true" />
      {{ formError }}
    </p>
    <SkFormField :label="t('integrations.fields.name')" :error="fieldErrors.name" required>
      <template #default="{ attrs, invalid }">
        <TextControl
          v-bind="attrs"
          :model-value="form.name"
          :aria-invalid="invalid ? 'true' : undefined"
          @update:model-value="onNameInput"
        />
      </template>
    </SkFormField>
    <SkFormField
      v-if="!editing"
      :label="t('integrations.fields.id')"
      :help="t('integrations.fields.idHelp')"
      :error="fieldErrors.id"
      required
    >
      <template #default="{ attrs, invalid }">
        <TextControl
          v-bind="attrs"
          :model-value="form.id"
          mono
          :aria-invalid="invalid ? 'true' : undefined"
          @update:model-value="
            (v) => {
              idTouched = true
              form.id = v
            }
          "
        />
      </template>
    </SkFormField>
    <div class="flex flex-wrap gap-4">
      <SkFormField :label="t('integrations.fields.kind')" required>
        <template #default="{ attrs }">
          <SelectControl
            v-bind="attrs"
            :model-value="form.kind"
            :options="kindOptions"
            @update:model-value="onKindChange"
          />
        </template>
      </SkFormField>
      <SkFormField :label="t('integrations.fields.severity')">
        <template #default="{ attrs }">
          <SelectControl
            v-bind="attrs"
            :model-value="form.severity"
            :options="severityOptions"
            @update:model-value="(v) => (form.severity = v ?? 'warning')"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('integrations.fields.cooldown')"
        :help="t('integrations.fields.cooldownHelp')"
        :error="fieldErrors.cooldown"
        required
      >
        <template #default="{ attrs, invalid }">
          <NumberControl
            v-bind="attrs"
            :model-value="form.cooldown"
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="(v) => (form.cooldown = v)"
          />
        </template>
      </SkFormField>
    </div>

    <SettingsFields
      v-if="spec.length"
      v-model="model"
      :spec="spec"
      :sites="sites"
      option-group="alertField"
    />

    <fieldset class="flex flex-col gap-2">
      <legend class="text-sm font-medium">{{ t('integrations.fields.channels') }}</legend>
      <template v-if="channels.length">
        <SwitchControl
          v-for="c in channels"
          :key="c.id"
          :model-value="form.channelIds.includes(c.id)"
          :label="c.name"
          @update:model-value="toggleChannel(c.id, $event)"
        />
      </template>
      <p v-else class="text-sm text-sk-muted" data-testid="no-channels">
        {{ t('integrations.alerts.noChannels') }}
        <RouterLink to="/integrations/channels" class="underline">
          {{ t('integrations.alerts.noChannelsLink') }}
        </RouterLink>
      </p>
    </fieldset>
    <SwitchControl v-model="form.enabled" :label="t('integrations.fields.enabled')" />
  </SkFormDialog>

  <SkConfirmDialog
    v-if="canWrite"
    :open="toDelete !== undefined"
    danger
    :busy="deleting"
    :title="t('integrations.alerts.confirmTitle', { name: toDelete?.name ?? '' })"
    :message="t('integrations.alerts.confirmMessage')"
    :confirm-label="t('common.actions.delete')"
    @update:open="toDelete = undefined"
    @confirm="remove"
  />
</template>
