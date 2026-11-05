<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import ListControl from './controls/ListControl.vue'
import SelectControl from './controls/SelectControl.vue'
import SwitchControl from './controls/SwitchControl.vue'
import NumberControl from './controls/NumberControl.vue'
import type { PolicyFieldSpec } from './policyFields'

defineProps<{
  spec: PolicyFieldSpec
  attrs: Record<string, unknown>
  value: unknown
  disabled?: boolean
  invalid?: boolean
  blockPages: string[]
}>()
const emit = defineEmits<{ update: [value: unknown] }>()

const { t } = useI18n()

const asString = (v: unknown) => (typeof v === 'string' ? v : undefined)
const asNumber = (v: unknown) => (typeof v === 'number' ? v : undefined)
const asBoolean = (v: unknown) => (typeof v === 'boolean' ? v : undefined)
const asList = (v: unknown) => (Array.isArray(v) ? v.map(String) : undefined)
</script>

<template>
  <SelectControl
    v-if="spec.kind === 'select'"
    v-bind="attrs"
    :model-value="asString(value)"
    :options="(spec.options ?? []).map((o) => ({ value: o, label: t(`sites.options.${o}`) }))"
    :empty-label="t('sites.notSet')"
    :disabled="disabled"
    :aria-invalid="invalid ? 'true' : undefined"
    @update:model-value="emit('update', $event)"
  />
  <SelectControl
    v-else-if="spec.kind === 'blockpage'"
    v-bind="attrs"
    :model-value="asString(value)"
    :options="blockPages.map((id) => ({ value: id, label: id }))"
    :empty-label="t('sites.notSet')"
    :disabled="disabled"
    :aria-invalid="invalid ? 'true' : undefined"
    @update:model-value="emit('update', $event)"
  />
  <NumberControl
    v-else-if="spec.kind === 'number'"
    v-bind="attrs"
    :min="spec.min"
    :max="spec.max"
    :model-value="asNumber(value)"
    :disabled="disabled"
    :aria-invalid="invalid ? 'true' : undefined"
    @update:model-value="emit('update', $event)"
  />
  <ListControl
    v-else-if="spec.kind === 'list'"
    v-bind="attrs"
    :model-value="asList(value)"
    :disabled="disabled"
    :aria-invalid="invalid ? 'true' : undefined"
    @update:model-value="emit('update', $event)"
  />
  <SwitchControl
    v-else
    v-bind="attrs"
    :model-value="asBoolean(value)"
    :label="t('sites.enabled')"
    :disabled="disabled"
    @update:model-value="emit('update', $event)"
  />
</template>
