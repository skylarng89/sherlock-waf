<script setup lang="ts" generic="T">
import SkFormField from '@/components/SkFormField.vue'
import SkInheritedField from '@/components/SkInheritedField.vue'

/**
 * One policy value. With `inheritable` it is a SkInheritedField (override switch plus the
 * inherited value and its source); without, a plain field (the global defaults page).
 */
defineProps<{
  label: string
  help?: string
  error?: string
  modelValue?: T
  inheritable?: boolean
  inherited?: T
  sourceLabel?: string
  format?: (value: T) => string
  defaultOverride?: T
  disabled?: boolean
}>()
const emit = defineEmits<{ 'update:modelValue': [value: T | undefined] }>()
</script>

<template>
  <SkInheritedField
    v-if="inheritable"
    :model-value="modelValue"
    :inherited="inherited"
    :source-label="sourceLabel"
    :default-override="defaultOverride"
    :format="format"
    :label="label"
    :help="help"
    :error="error"
    :disabled="disabled"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <template #default="{ attrs, value, update, disabled: off }">
      <slot
        :attrs="attrs"
        :value="value"
        :update="update"
        :disabled="off"
        :invalid="Boolean(error)"
      />
    </template>
  </SkInheritedField>
  <SkFormField v-else :label="label" :help="help" :error="error">
    <template #default="{ attrs, invalid }">
      <slot
        :attrs="attrs"
        :value="modelValue"
        :update="(v: T | undefined) => emit('update:modelValue', v)"
        :disabled="disabled"
        :invalid="invalid"
      />
    </template>
  </SkFormField>
</template>
