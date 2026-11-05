<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import SkFormField from '@/components/SkFormField.vue'
import SkInheritedField from '@/components/SkInheritedField.vue'
import { getAt, setAt, type JsonObject } from './lib/json'
import { resolveInherited, type Policy, type PolicyLayer } from './lib/layers'
import PolicyControl from './PolicyControl.vue'
import { fieldKey, policyFields } from './policyFields'

/**
 * The editable policy fields. With `layers` every field is a SkInheritedField showing the
 * value (and level) it inherits from; without, plain fields (global defaults page).
 */
const props = defineProps<{
  layers?: PolicyLayer[]
  blockPages: string[]
  disabled?: boolean
  /** Receives the path relative to the policy, e.g. `waf.paranoia_level`. */
  errorFor: (path: string) => string | undefined
}>()

const model = defineModel<Policy>({ required: true })
const { t } = useI18n()

function set(path: string, value: unknown) {
  model.value = setAt(model.value as JsonObject, path, value) as Policy
}

function format(value: unknown): string {
  if (typeof value === 'boolean') return value ? t('common.yes') : t('common.no')
  if (Array.isArray(value)) return value.length ? value.join(', ') : t('common.none')
  if (typeof value === 'string') return t(`sites.options.${value}`, value)
  return String(value)
}

function resolved(path: string) {
  return resolveInherited(props.layers ?? [], path)
}
</script>

<template>
  <div class="flex flex-col gap-4" data-testid="policy-form">
    <template v-for="f in policyFields" :key="f.path">
      <SkInheritedField
        v-if="layers"
        :model-value="getAt(model, f.path)"
        :inherited="resolved(f.path).value"
        :source-label="resolved(f.path).label"
        :format="format"
        :label="t(`sites.policy.${fieldKey(f.path)}.label`)"
        :help="t(`sites.policy.${fieldKey(f.path)}.help`)"
        :error="errorFor(f.path)"
        :disabled="disabled"
        @update:model-value="set(f.path, $event)"
      >
        <template #default="{ attrs, value, update, disabled: off }">
          <PolicyControl
            :spec="f"
            :attrs="attrs"
            :value="value"
            :disabled="off"
            :invalid="Boolean(errorFor(f.path))"
            :block-pages="blockPages"
            @update="update"
          />
        </template>
      </SkInheritedField>
      <SkFormField
        v-else
        :label="t(`sites.policy.${fieldKey(f.path)}.label`)"
        :help="t(`sites.policy.${fieldKey(f.path)}.help`)"
        :error="errorFor(f.path)"
      >
        <template #default="{ attrs, invalid }">
          <PolicyControl
            :spec="f"
            :attrs="attrs"
            :value="getAt(model, f.path)"
            :disabled="disabled"
            :invalid="invalid"
            :block-pages="blockPages"
            @update="set(f.path, $event)"
          />
        </template>
      </SkFormField>
    </template>
  </div>
</template>
