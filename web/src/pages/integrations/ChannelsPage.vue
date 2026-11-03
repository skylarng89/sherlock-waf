<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'
import SkEmptyState from '@/components/SkEmptyState.vue'
import SkFormDialog from '@/components/SkFormDialog.vue'
import SkFormField from '@/components/SkFormField.vue'
import SkPageHeader from '@/components/SkPageHeader.vue'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import SwitchControl from '@/pages/sites/controls/SwitchControl.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import { useSessionStore } from '@/stores/session'
import { useToastStore } from '@/stores/toasts'
import SettingsFields from './SettingsFields.vue'
import TestOutcome from './TestOutcome.vue'
import {
  CHANNEL_SPECS,
  CHANNEL_TYPES,
  ID_PATTERN,
  defaultsFor,
  modelFromSettings,
  settingsFromModel,
  slugify,
  type Model,
  type Settings,
} from './spec'

type Channel = components['schemas']['NotificationChannel']
type ChannelType = Channel['type']
type Outcome = { ok: boolean; error?: string }

const { t } = useI18n()
const session = useSessionStore()
const toasts = useToastStore()
const { client, call } = useApi()
const canWrite = computed(() => session.can('config:write'))

const items = ref<Channel[]>([])
const state = ref<'loading' | 'ready' | 'error'>('loading')
const announcement = ref('')
const pageError = ref('')
const rowTest = ref<{ name: string; result?: Outcome; testing: boolean }>()

async function load() {
  try {
    items.value = (await call(client.GET('/notification-channels'), { toast: false })).data.items
    state.value = 'ready'
  } catch {
    state.value = 'error'
  }
}
onMounted(load)

const dialogOpen = ref(false)
const editing = ref<Channel>()
const form = ref({ id: '', name: '', type: 'slack' as ChannelType, enabled: true })
const idTouched = ref(false)
const model = ref<Model>({})
const busy = ref(false)
const formError = ref('')
const fieldErrors = ref<Record<string, string>>({})
const dialogTest = ref<{ result?: Outcome; testing: boolean }>({ testing: false })

const spec = computed(() => CHANNEL_SPECS[form.value.type] ?? [])
const typeOptions = CHANNEL_TYPES.map((v) => ({
  value: v,
  label: t(`integrations.options.channel.${v}`),
}))

function resetModel(type: ChannelType, settings?: Settings) {
  const s = CHANNEL_SPECS[type] ?? []
  model.value = settings ? modelFromSettings(s, settings) : defaultsFor(s)
}

function clearMessages() {
  formError.value = ''
  fieldErrors.value = {}
  dialogTest.value = { testing: false }
}

function openCreate() {
  editing.value = undefined
  form.value = { id: '', name: '', type: 'slack', enabled: true }
  idTouched.value = false
  resetModel('slack')
  clearMessages()
  dialogOpen.value = true
}

function openEdit(c: Channel) {
  editing.value = c
  form.value = { id: c.id, name: c.name, type: c.type, enabled: c.enabled }
  resetModel(c.type, c.settings)
  clearMessages()
  dialogOpen.value = true
}

function onTypeChange(type: ChannelType | undefined) {
  if (!type) return
  form.value.type = type
  resetModel(type, editing.value?.type === type ? editing.value.settings : undefined)
  dialogTest.value = { testing: false }
}

function onNameInput(name: string) {
  form.value.name = name
  if (!idTouched.value && !editing.value) form.value.id = slugify(name)
}

function currentSettings(): Settings {
  const base = editing.value?.type === form.value.type ? editing.value.settings : undefined
  return settingsFromModel(spec.value, model.value, base).settings
}

function problemText(e: unknown): string {
  return isApiError(e) ? (e.detail ?? e.title) : t('integrations.errors.generic')
}

async function save() {
  formError.value = ''
  const errors: Record<string, string> = {}
  if (form.value.name.trim() === '') errors.name = t('integrations.errors.nameRequired')
  if (!editing.value && !ID_PATTERN.test(form.value.id)) errors.id = t('integrations.errors.id')
  fieldErrors.value = errors
  if (Object.keys(errors).length > 0) return

  busy.value = true
  try {
    await call(
      client.PUT('/notification-channels/{id}', {
        params: { path: { id: form.value.id } },
        body: {
          name: form.value.name.trim(),
          type: form.value.type,
          enabled: form.value.enabled,
          settings: currentSettings(),
        },
      }),
      { toast: false },
    )
    dialogOpen.value = false
    announcement.value = t('integrations.channels.saved', { name: form.value.name })
    toasts.success(announcement.value)
    await load()
  } catch (e) {
    formError.value = problemText(e)
  } finally {
    busy.value = false
  }
}

async function runTest(body: {
  id?: string
  type: ChannelType
  settings: Settings
}): Promise<Outcome> {
  try {
    return (await call(client.POST('/notification-channels/test', { body }), { toast: false })).data
  } catch (e) {
    return { ok: false, error: problemText(e) }
  }
}

async function testDialog() {
  dialogTest.value = { testing: true }
  const result = await runTest({
    ...(editing.value ? { id: editing.value.id } : {}),
    type: form.value.type,
    settings: currentSettings(),
  })
  dialogTest.value = { testing: false, result }
}

async function testRow(c: Channel) {
  rowTest.value = { name: c.name, testing: true }
  rowTest.value = {
    name: c.name,
    testing: false,
    result: await runTest({ id: c.id, type: c.type, settings: c.settings }),
  }
}

async function toggle(c: Channel, enabled: boolean) {
  pageError.value = ''
  try {
    await call(
      client.PUT('/notification-channels/{id}', {
        params: { path: { id: c.id } },
        body: { name: c.name, type: c.type, enabled, settings: c.settings },
      }),
      { toast: false },
    )
    announcement.value = t(enabled ? 'integrations.enabledNamed' : 'integrations.disabledNamed', {
      name: c.name,
    })
  } catch (e) {
    pageError.value = problemText(e)
  }
  await load()
}

const toDelete = ref<Channel>()
const deleting = ref(false)

async function remove() {
  const c = toDelete.value
  if (!c) return
  deleting.value = true
  pageError.value = ''
  try {
    await call(client.DELETE('/notification-channels/{id}', { params: { path: { id: c.id } } }), {
      toast: false,
    })
    announcement.value = t('integrations.channels.deleted', { name: c.name })
    toasts.success(announcement.value)
  } catch (e) {
    // 409: alert rules still notify this channel; the server names them.
    pageError.value = problemText(e)
  } finally {
    toDelete.value = undefined
    deleting.value = false
  }
  await load()
}
</script>

<template>
  <SkPageHeader
    :title="t('integrations.channels.title')"
    :description="t('integrations.channels.description')"
  >
    <template #actions>
      <Button
        v-if="canWrite"
        type="button"
        icon="ti ti-plus"
        :label="t('integrations.channels.add')"
        data-testid="channel-add"
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
    data-testid="page-error"
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
      {{ t('integrations.channels.loadFailed') }}
    </p>
    <Button :label="t('common.actions.retry')" severity="secondary" @click="load()" />
  </div>
  <SkEmptyState
    v-else-if="items.length === 0"
    icon="ti ti-message-circle"
    :title="t('integrations.channels.emptyTitle')"
    :description="t('integrations.channels.emptyDescription')"
  />
  <div
    v-else
    class="overflow-x-auto"
    tabindex="0"
    role="region"
    :aria-label="t('integrations.channels.scroll')"
  >
    <table class="w-full text-left" data-testid="channels-table">
      <caption class="sr-only">
        {{
          t('integrations.channels.caption')
        }}
      </caption>
      <thead>
        <tr class="border-b border-sk-border-strong">
          <th scope="col" class="p-2">{{ t('integrations.cols.name') }}</th>
          <th scope="col" class="p-2">{{ t('integrations.cols.type') }}</th>
          <th scope="col" class="p-2">{{ t('integrations.cols.enabled') }}</th>
          <th v-if="canWrite" scope="col" class="p-2">{{ t('integrations.cols.actions') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="c in items"
          :key="c.id"
          class="border-b border-sk-border"
          :data-testid="`channel-${c.id}`"
        >
          <th scope="row" class="p-2 font-medium">{{ c.name }}</th>
          <td class="p-2">{{ t(`integrations.options.channel.${c.type}`) }}</td>
          <td class="p-2">
            <SwitchControl
              v-if="canWrite"
              :model-value="c.enabled"
              :label="t('integrations.enabledNamed', { name: c.name })"
              @update:model-value="toggle(c, $event)"
            />
            <span v-else>{{ c.enabled ? t('common.yes') : t('common.no') }}</span>
          </td>
          <td v-if="canWrite" class="p-2">
            <div class="flex flex-wrap gap-2">
              <button
                type="button"
                class="rounded-sk border border-sk-border-strong px-2 py-1"
                :aria-label="t('integrations.testNamed', { name: c.name })"
                @click="testRow(c)"
              >
                <i class="ti ti-plug-connected" aria-hidden="true" />
                {{ t('integrations.test.button') }}
              </button>
              <button
                type="button"
                class="rounded-sk border border-sk-border-strong px-2 py-1"
                :aria-label="t('integrations.editNamed', { name: c.name })"
                @click="openEdit(c)"
              >
                <i class="ti ti-pencil" aria-hidden="true" />
                {{ t('common.actions.edit') }}
              </button>
              <button
                type="button"
                class="rounded-sk border border-sk-border-strong px-2 py-1"
                :aria-label="t('integrations.deleteNamed', { name: c.name })"
                @click="toDelete = c"
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
    :title="editing ? t('integrations.channels.editTitle') : t('integrations.channels.addTitle')"
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
    <SwitchControl v-model="form.enabled" :label="t('integrations.fields.enabled')" />

    <SettingsFields
      v-model="model"
      :spec="spec"
      :stored="editing?.type === form.type ? editing.settings : undefined"
      :errors="fieldErrors"
      option-group="channelField"
    />

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
    :title="t('integrations.channels.confirmTitle', { name: toDelete?.name ?? '' })"
    :message="t('integrations.channels.confirmMessage')"
    :confirm-label="t('common.actions.delete')"
    @update:open="toDelete = undefined"
    @confirm="remove"
  />
</template>
