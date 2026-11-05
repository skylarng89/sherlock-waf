<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkFormDialog from '@/components/SkFormDialog.vue'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { relativeTime } from '@/pages/access/time'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import SwitchControl from '@/pages/sites/controls/SwitchControl.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import { controlClass } from '@/pages/sites/controls/classes'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import SettingsFields from './SettingsFields.vue'
import TestOutcome from './TestOutcome.vue'
import {
  EXPORTER_SPECS,
  ID_PATTERN,
  defaultsFor,
  formatBytes,
  modelFromSettings,
  settingsFromModel,
  slugify,
  type Model,
  type Settings,
} from './spec'

type Exporter = components['schemas']['Exporter']
type Stream = Exporter['stream']
type Outcome = { ok: boolean; error?: string }

const REFRESH_MS = 15_000
const STREAMS: Stream[] = ['events', 'audit', 'both']

const { t } = useI18n()
const session = useSessionStore()
const toasts = useToastStore()
const { client, call } = useApi()
const canWrite = computed(() => session.can('config:write'))

const items = ref<Exporter[]>([])
const types = ref<string[]>(Object.keys(EXPORTER_SPECS))
const state = ref<'loading' | 'ready' | 'error'>('loading')
const now = ref(Date.now())
const announcement = ref('')
const pageError = ref('')
const rowTest = ref<{ name: string; result?: Outcome; testing: boolean }>()
let timer: ReturnType<typeof setInterval> | undefined

// --- list ---

async function load(silent = false) {
  if (!silent) state.value = 'loading'
  try {
    items.value = (await call(client.GET('/exporters'), { toast: false })).data.items
    state.value = 'ready'
  } catch {
    // A failed background refresh keeps the table already shown.
    if (!silent || state.value !== 'ready') state.value = 'error'
  }
  now.value = Date.now()
}

async function loadTypes() {
  try {
    const res = await call(client.GET('/integrations/types'), { toast: false })
    if (res.data.exporters.length > 0) types.value = res.data.exporters
  } catch {
    // The built-in types stay available.
  }
}

function tick() {
  if (!document.hidden && !dialogOpen.value) void load(true)
}

onMounted(() => {
  void load()
  void loadTypes()
  timer = setInterval(tick, REFRESH_MS)
  document.addEventListener('visibilitychange', tick)
})
onBeforeUnmount(() => {
  if (timer !== undefined) clearInterval(timer)
  document.removeEventListener('visibilitychange', tick)
})

// --- dialog ---

const dialogOpen = ref(false)
const editing = ref<Exporter>()
const form = ref({ id: '', name: '', type: 'syslog', stream: 'events' as Stream, enabled: true })
const idTouched = ref(false)
const model = ref<Model>({})
const jsonText = ref('{}')
const busy = ref(false)
const formError = ref('')
const fieldErrors = ref<Record<string, string>>({})
const dialogTest = ref<{ result?: Outcome; testing: boolean }>({ testing: false })

const spec = computed(() => EXPORTER_SPECS[form.value.type])
const typeOptions = computed(() => types.value.map((v) => ({ value: v, label: v })))

function resetModel(type: string, settings?: Settings) {
  const s = EXPORTER_SPECS[type]
  if (s) model.value = settings ? modelFromSettings(s, settings) : defaultsFor(s)
  else jsonText.value = JSON.stringify(settings ?? {}, null, 2)
}

function openCreate() {
  editing.value = undefined
  form.value = {
    id: '',
    name: '',
    type: types.value[0] ?? 'syslog',
    stream: 'events',
    enabled: true,
  }
  idTouched.value = false
  resetModel(form.value.type)
  clearMessages()
  dialogOpen.value = true
}

function openEdit(e: Exporter) {
  editing.value = e
  form.value = { id: e.id, name: e.name, type: e.type, stream: e.stream, enabled: e.enabled }
  resetModel(e.type, e.settings)
  clearMessages()
  dialogOpen.value = true
}

function clearMessages() {
  formError.value = ''
  fieldErrors.value = {}
  dialogTest.value = { testing: false }
}

function onTypeChange(type: string | undefined) {
  if (!type) return
  form.value.type = type
  // A different type has different settings; stored secrets belong to the old one.
  resetModel(type, editing.value?.type === type ? editing.value.settings : undefined)
  dialogTest.value = { testing: false }
}

function onNameInput(name: string) {
  form.value.name = name
  if (!idTouched.value && !editing.value) form.value.id = slugify(name)
}

/** The settings document for the current form, or undefined with an error shown. */
function currentSettings(): Settings | undefined {
  fieldErrors.value = {}
  const s = spec.value
  if (!s) {
    try {
      const parsed: unknown = JSON.parse(jsonText.value)
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error()
      return parsed as Settings
    } catch {
      fieldErrors.value = { json: t('integrations.errors.json') }
      return undefined
    }
  }
  const base = editing.value?.type === form.value.type ? editing.value.settings : undefined
  const built = settingsFromModel(s, model.value, base)
  if (built.badHeaders !== undefined) {
    fieldErrors.value = { headers: t('integrations.errors.header', { line: built.badHeaders }) }
    return undefined
  }
  return built.settings
}

function problemText(e: unknown): string {
  return isApiError(e) ? (e.detail ?? e.title) : t('integrations.errors.generic')
}

async function save() {
  formError.value = ''
  const errors: Record<string, string> = {}
  if (form.value.name.trim() === '') errors.name = t('integrations.errors.nameRequired')
  if (!editing.value && !ID_PATTERN.test(form.value.id)) errors.id = t('integrations.errors.id')
  const settings = currentSettings()
  fieldErrors.value = { ...fieldErrors.value, ...errors }
  if (settings === undefined || Object.keys(errors).length > 0) return

  busy.value = true
  try {
    await call(
      client.PUT('/exporters/{id}', {
        params: { path: { id: form.value.id } },
        body: {
          name: form.value.name.trim(),
          type: form.value.type,
          stream: form.value.stream,
          enabled: form.value.enabled,
          settings,
        },
      }),
      { toast: false },
    )
    dialogOpen.value = false
    announcement.value = t('integrations.exporters.saved', { name: form.value.name })
    toasts.success(announcement.value)
    await load(true)
  } catch (e) {
    formError.value = problemText(e)
  } finally {
    busy.value = false
  }
}

async function runTest(body: {
  id?: string
  type: string
  stream: Stream
  settings: Settings
}): Promise<Outcome> {
  try {
    return (await call(client.POST('/exporters/test', { body }), { toast: false })).data
  } catch (e) {
    return { ok: false, error: problemText(e) }
  }
}

async function testDialog() {
  const settings = currentSettings()
  if (settings === undefined) return
  dialogTest.value = { testing: true }
  const result = await runTest({
    ...(editing.value ? { id: editing.value.id } : {}),
    type: form.value.type,
    stream: form.value.stream,
    settings,
  })
  dialogTest.value = { testing: false, result }
}

async function testRow(e: Exporter) {
  rowTest.value = { name: e.name, testing: true }
  const result = await runTest({ id: e.id, type: e.type, stream: e.stream, settings: e.settings })
  rowTest.value = { name: e.name, testing: false, result }
}

async function toggle(e: Exporter, enabled: boolean) {
  pageError.value = ''
  try {
    await call(
      client.PUT('/exporters/{id}', {
        params: { path: { id: e.id } },
        body: { name: e.name, type: e.type, stream: e.stream, enabled, settings: e.settings },
      }),
      { toast: false },
    )
    announcement.value = t(enabled ? 'integrations.enabledNamed' : 'integrations.disabledNamed', {
      name: e.name,
    })
  } catch (err) {
    pageError.value = problemText(err)
  }
  await load(true)
}

// --- delete ---

const toDelete = ref<Exporter>()
const deleting = ref(false)

async function remove() {
  const e = toDelete.value
  if (!e) return
  deleting.value = true
  pageError.value = ''
  try {
    await call(client.DELETE('/exporters/{id}', { params: { path: { id: e.id } } }), {
      toast: false,
    })
    toDelete.value = undefined
    announcement.value = t('integrations.exporters.deleted', { name: e.name })
    toasts.success(announcement.value)
  } catch (err) {
    toDelete.value = undefined
    pageError.value = problemText(err)
  } finally {
    deleting.value = false
  }
  await load(true)
}
</script>

<template>
  <SkPageHeader
    :title="t('integrations.exporters.title')"
    :description="t('integrations.exporters.description')"
  >
    <template #actions>
      <Button
        v-if="canWrite"
        type="button"
        icon="ti ti-plus"
        :label="t('integrations.exporters.add')"
        data-testid="exporter-add"
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
      {{ t('integrations.exporters.loadFailed') }}
    </p>
    <Button :label="t('common.actions.retry')" severity="secondary" @click="load()" />
  </div>
  <SkEmptyState
    v-else-if="items.length === 0"
    icon="ti ti-send"
    :title="t('integrations.exporters.emptyTitle')"
    :description="t('integrations.exporters.emptyDescription')"
  />
  <div
    v-else
    class="overflow-x-auto"
    tabindex="0"
    role="region"
    :aria-label="t('integrations.exporters.scroll')"
  >
    <table class="w-full text-left" data-testid="exporters-table">
      <caption class="sr-only">
        {{
          t('integrations.exporters.caption')
        }}
      </caption>
      <thead>
        <tr class="border-b border-sk-border-strong">
          <th scope="col" class="p-2">{{ t('integrations.cols.name') }}</th>
          <th scope="col" class="p-2">{{ t('integrations.cols.type') }}</th>
          <th scope="col" class="p-2">{{ t('integrations.cols.stream') }}</th>
          <th scope="col" class="p-2">{{ t('integrations.cols.enabled') }}</th>
          <th scope="col" class="p-2">{{ t('integrations.cols.delivery') }}</th>
          <th scope="col" class="p-2">{{ t('integrations.cols.lastSuccess') }}</th>
          <th scope="col" class="p-2">{{ t('integrations.cols.actions') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="e in items"
          :key="e.id"
          class="border-b border-sk-border align-top"
          :data-testid="`exporter-${e.id}`"
        >
          <th scope="row" class="p-2 font-medium">{{ e.name }}</th>
          <td class="p-2 font-mono text-sm">{{ e.type }}</td>
          <td class="p-2">{{ t(`integrations.options.stream.${e.stream}`) }}</td>
          <td class="p-2">
            <SwitchControl
              v-if="canWrite"
              :model-value="e.enabled"
              :label="t('integrations.enabledNamed', { name: e.name })"
              class="[&>input]:size-5"
              @update:model-value="toggle(e, $event)"
            />
            <span v-else>{{ e.enabled ? t('common.yes') : t('common.no') }}</span>
          </td>
          <td class="p-2 text-sm">
            <p v-if="e.status?.running" class="inline-flex items-center gap-1 text-sk-success">
              <i class="ti ti-player-play" aria-hidden="true" />
              {{ t('integrations.exporters.running') }}
            </p>
            <p v-else class="inline-flex items-center gap-1 text-sk-muted">
              <i class="ti ti-player-pause" aria-hidden="true" />
              {{ t('integrations.exporters.stopped') }}
            </p>
            <dl v-if="e.status?.running" class="mt-1 grid grid-cols-[auto_1fr] gap-x-2">
              <dt class="text-sk-muted">{{ t('integrations.stats.sent') }}</dt>
              <dd>{{ e.status.sent }}</dd>
              <dt class="text-sk-muted">{{ t('integrations.stats.pending') }}</dt>
              <dd>{{ e.status.pending }}</dd>
              <dt class="text-sk-muted">{{ t('integrations.stats.dropped') }}</dt>
              <dd :class="e.status.dropped > 0 ? 'font-medium text-sk-danger' : ''">
                {{ e.status.dropped }}
              </dd>
              <dt class="text-sk-muted">{{ t('integrations.stats.spool') }}</dt>
              <dd>{{ formatBytes(e.status.spool_bytes) }}</dd>
            </dl>
          </td>
          <td class="p-2 text-sm">
            <time v-if="e.status?.last_success" :datetime="e.status.last_success">
              {{ relativeTime(e.status.last_success, now) }}
            </time>
            <span v-else class="text-sk-muted">{{ t('integrations.never') }}</span>
            <p v-if="e.status?.last_error" class="mt-1 text-sk-danger">
              <i class="ti ti-alert-triangle" aria-hidden="true" />
              {{ e.status.last_error }}
              <time v-if="e.status.last_error_at" :datetime="e.status.last_error_at">
                ({{ relativeTime(e.status.last_error_at, now) }})
              </time>
            </p>
          </td>
          <td class="p-2">
            <div class="flex flex-wrap gap-2">
              <button
                v-if="canWrite"
                type="button"
                class="rounded-sk border border-sk-border-strong px-2 py-1"
                :aria-label="t('integrations.testNamed', { name: e.name })"
                @click="testRow(e)"
              >
                <i class="ti ti-plug-connected" aria-hidden="true" />
                {{ t('integrations.test.button') }}
              </button>
              <button
                v-if="canWrite"
                type="button"
                class="rounded-sk border border-sk-border-strong px-2 py-1"
                :aria-label="t('integrations.editNamed', { name: e.name })"
                @click="openEdit(e)"
              >
                <i class="ti ti-pencil" aria-hidden="true" />
                {{ t('common.actions.edit') }}
              </button>
              <button
                v-if="canWrite"
                type="button"
                class="rounded-sk border border-sk-border-strong px-2 py-1"
                :aria-label="t('integrations.deleteNamed', { name: e.name })"
                @click="toDelete = e"
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

  <div class="mt-3" data-testid="row-test">
    <p v-if="rowTest" class="text-sm font-medium">{{ rowTest.name }}</p>
    <TestOutcome :result="rowTest?.result" :testing="rowTest?.testing" />
  </div>

  <SkFormDialog
    v-if="canWrite"
    v-model:open="dialogOpen"
    :title="editing ? t('integrations.exporters.editTitle') : t('integrations.exporters.addTitle')"
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
      <SkFormField :label="t('integrations.fields.type')" required>
        <template #default="{ attrs }">
          <SelectControl
            v-bind="attrs"
            :model-value="form.type"
            :options="typeOptions"
            @update:model-value="onTypeChange"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('integrations.fields.stream')"
        :help="t('integrations.fields.streamHelp')"
      >
        <template #default="{ attrs }">
          <SelectControl
            v-bind="attrs"
            :model-value="form.stream"
            :options="
              STREAMS.map((s) => ({ value: s, label: t(`integrations.options.stream.${s}`) }))
            "
            @update:model-value="(v) => (form.stream = v ?? 'events')"
          />
        </template>
      </SkFormField>
    </div>
    <SwitchControl v-model="form.enabled" :label="t('integrations.fields.enabled')" />

    <SettingsFields
      v-if="spec"
      v-model="model"
      :spec="spec"
      :stored="editing?.type === form.type ? editing.settings : undefined"
      :errors="fieldErrors"
      option-group="exporter"
    />
    <SkFormField
      v-else
      :label="t('integrations.fields.json')"
      :help="t('integrations.fields.jsonHelp')"
      :error="fieldErrors.json"
    >
      <template #default="{ attrs }">
        <textarea
          v-bind="attrs"
          v-model="jsonText"
          rows="8"
          spellcheck="false"
          :class="[controlClass, 'font-mono']"
        />
      </template>
    </SkFormField>

    <template #footer-extra>
      <TestOutcome :result="dialogTest.result" :testing="dialogTest.testing" class="mr-auto" />
      <button
        type="button"
        class="rounded-sk border border-sk-border-strong px-4 py-2 hover:bg-sk-surface-muted"
        :disabled="busy || dialogTest.testing"
        data-testid="dialog-test"
        @click="testDialog"
      >
        <i class="ti ti-plug-connected" aria-hidden="true" />
        {{ t('integrations.test.button') }}
      </button>
    </template>
  </SkFormDialog>

  <SkConfirmDialog
    v-if="canWrite"
    :open="toDelete !== undefined"
    danger
    :busy="deleting"
    :title="t('integrations.exporters.confirmTitle', { name: toDelete?.name ?? '' })"
    :message="t('integrations.exporters.confirmMessage')"
    :confirm-label="t('common.actions.delete')"
    @update:open="toDelete = undefined"
    @confirm="remove"
  />
</template>
