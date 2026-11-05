<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import SwitchControl from '@/pages/sites/controls/SwitchControl.vue'
import { getAt, setAt, type JsonObject } from '@/pages/sites/lib/json'
import { resolveInherited, type Policy, type PolicyLayer } from '@/pages/sites/lib/layers'
import CountriesEditor from './CountriesEditor.vue'
import NameListEditor from './NameListEditor.vue'
import PasswordGateEditor from './PasswordGateEditor.vue'
import PolicyRow from './PolicyRow.vue'
import {
  NAME_LIST_FIELDS,
  resolveNameList,
  type AclPolicy,
  type NameList,
  type NameListField,
} from './policy'
import ReputationEditor from './ReputationEditor.vue'

const props = defineProps<{
  /** Parent levels, closest first. Without them every field is plain (global defaults). */
  layers?: PolicyLayer[]
  /** Names of the global IP lists. */
  known: string[]
  disabled?: boolean
  /** Receives the path relative to the policy, e.g. `acl.countries.mode`. */
  errorFor: (path: string) => string | undefined
}>()
const model = defineModel<Policy>({ required: true })
const { t } = useI18n()

const inheritable = computed(() => props.layers !== undefined)

function set(path: string, value: unknown) {
  model.value = setAt(model.value as JsonObject, path, value) as Policy
}

function errorOr(...paths: string[]): string | undefined {
  for (const p of paths) {
    const e = props.errorFor(p)
    if (e) return e
  }
  return undefined
}

function resolved(path: string) {
  return resolveInherited(props.layers ?? [], path)
}

const listNames = (field: NameListField) => resolveNameList(props.layers ?? [], field)

function formatNames(value: string[]): string {
  return value.length ? value.join(', ') : t('common.none')
}

function formatNameList(value: NameList): string {
  return formatNames(Array.isArray(value) ? value : (value.add ?? []))
}

function formatCountries(value: NonNullable<AclPolicy['countries']>): string {
  return `${t(`access.acl.countries.modes.${value.mode ?? 'off'}`)}: ${formatNames(value.list ?? [])}`
}

function formatReputation(value: NonNullable<AclPolicy['reputation']>): string {
  return value.enabled === false
    ? t('access.acl.reputation.off')
    : t('access.acl.reputation.on', { action: t(`access.actions.${value.action ?? 'block'}`) })
}

// The hash is never shown, not even as inherited text.
function formatGate(value: NonNullable<AclPolicy['password_gate']>): string {
  return value.enabled === false
    ? t('access.acl.passwordGate.off')
    : t('access.acl.passwordGate.on', { username: value.username ?? '' })
}

function nameListValue(field: NameListField): NameList | undefined {
  return getAt(model.value, `acl.${field}`) as NameList | undefined
}
function inheritedList(field: NameListField): NameList | undefined {
  return listNames(field).names
}
function defaultList(field: NameListField): NameList {
  return listNames(field).names ?? []
}
const bypassValue = computed(
  () => getAt(model.value, 'acl.allow_bypass_waf') as boolean | undefined,
)

const bypass = computed(() => getAt(model.value, 'acl.allow_bypass_waf') === true)
const inheritedBypass = computed(() => resolved('acl.allow_bypass_waf').value === true)
</script>

<template>
  <div class="flex flex-col gap-4" data-testid="acl-form">
    <p class="rounded-sk border border-sk-border bg-sk-surface-muted p-3 text-sm">
      <i class="ti ti-list-numbers" aria-hidden="true" />
      {{ t('access.acl.precedence') }}
    </p>

    <PolicyRow
      v-for="field in NAME_LIST_FIELDS"
      :key="field"
      :model-value="nameListValue(field)"
      :inheritable="inheritable"
      :inherited="inheritedList(field)"
      :source-label="listNames(field).label"
      :format="formatNameList"
      :default-override="defaultList(field)"
      :label="t(`access.acl.${field}.label`)"
      :help="t(`access.acl.${field}.help`)"
      :error="errorOr(`acl.${field}`, `acl.${field}.add`, `acl.${field}.remove`)"
      :disabled="disabled"
      @update:model-value="set(`acl.${field}`, $event)"
    >
      <template #default="{ attrs, value, update, disabled: off }">
        <NameListEditor
          :model-value="value"
          :known="known"
          :inherited-names="inheritable ? (listNames(field).names ?? []) : undefined"
          :attrs="attrs"
          :label="t(`access.acl.${field}.label`)"
          :disabled="off"
          @update="update"
        />
      </template>
    </PolicyRow>

    <PolicyRow
      :model-value="getAt(model, 'acl.countries') as AclPolicy['countries']"
      :inheritable="inheritable"
      :inherited="resolved('acl.countries').value as AclPolicy['countries']"
      :source-label="resolved('acl.countries').label"
      :format="formatCountries"
      :default-override="{ mode: 'deny' }"
      :label="t('access.acl.countries.label')"
      :help="t('access.acl.countries.help')"
      :error="errorOr('acl.countries', 'acl.countries.mode', 'acl.countries.list')"
      :disabled="disabled"
      @update:model-value="set('acl.countries', $event)"
    >
      <template #default="{ attrs, value, update, disabled: off }">
        <CountriesEditor
          :model-value="value"
          :attrs="attrs"
          :label="t('access.acl.countries.label')"
          :disabled="off"
          @update="update"
        />
      </template>
    </PolicyRow>

    <PolicyRow
      :model-value="getAt(model, 'acl.reputation') as AclPolicy['reputation']"
      :inheritable="inheritable"
      :inherited="resolved('acl.reputation').value as AclPolicy['reputation']"
      :source-label="resolved('acl.reputation').label"
      :format="formatReputation"
      :default-override="{ enabled: true, action: 'block' }"
      :label="t('access.acl.reputation.label')"
      :help="t('access.acl.reputation.help')"
      :error="errorOr('acl.reputation', 'acl.reputation.enabled', 'acl.reputation.action')"
      :disabled="disabled"
      @update:model-value="set('acl.reputation', $event)"
    >
      <template #default="{ attrs, value, update, disabled: off }">
        <ReputationEditor :model-value="value" :attrs="attrs" :disabled="off" @update="update" />
      </template>
    </PolicyRow>

    <PolicyRow
      :model-value="getAt(model, 'acl.password_gate') as AclPolicy['password_gate']"
      :inheritable="inheritable"
      :inherited="resolved('acl.password_gate').value as AclPolicy['password_gate']"
      :source-label="resolved('acl.password_gate').label"
      :format="formatGate"
      :default-override="{ enabled: true }"
      :label="t('access.acl.passwordGate.label')"
      :help="t('access.acl.passwordGate.help')"
      :error="errorOr('acl.password_gate', 'acl.password_gate.enabled')"
      :disabled="disabled"
      @update:model-value="set('acl.password_gate', $event)"
    >
      <template #default="{ attrs, value, update, disabled: off }">
        <PasswordGateEditor
          :model-value="value"
          :attrs="attrs"
          :errors="{
            username: errorFor('acl.password_gate.username'),
            password_hash: errorFor('acl.password_gate.password_hash'),
          }"
          :disabled="off"
          @update="update"
        />
      </template>
    </PolicyRow>

    <PolicyRow
      :model-value="bypassValue"
      :inheritable="inheritable"
      :inherited="inheritable ? inheritedBypass : undefined"
      :source-label="resolved('acl.allow_bypass_waf').label"
      :label="t('access.acl.bypass.label')"
      :help="t('access.acl.bypass.help')"
      :error="errorFor('acl.allow_bypass_waf')"
      :disabled="disabled"
      @update:model-value="set('acl.allow_bypass_waf', $event)"
    >
      <template #default="{ attrs, value, update, disabled: off }">
        <SwitchControl
          v-bind="attrs"
          :model-value="value"
          :label="t('access.acl.bypass.switch')"
          :disabled="off"
          @update:model-value="update"
        />
      </template>
    </PolicyRow>
    <p
      v-if="bypass"
      role="alert"
      class="rounded-sk border border-sk-warning bg-sk-warning-bg p-3 text-sk-warning"
    >
      <i class="ti ti-alert-triangle" aria-hidden="true" />
      {{ t('access.acl.bypass.warning') }}
    </p>
    <p v-else class="text-sm text-sk-muted">
      <i class="ti ti-shield-check" aria-hidden="true" />
      {{ t('access.acl.bypass.inspected') }}
    </p>
  </div>
</template>
