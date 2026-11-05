<script setup lang="ts">
import { computed, useId } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps<{
  label: string
  help?: string
  /** Server or client validation message for this field. */
  error?: string
  required?: boolean
  /** Supply to reuse an id the control already has; generated otherwise. */
  id?: string
}>()

const { t } = useI18n()
const generated = useId()
const controlId = computed(() => props.id ?? `f-${generated}`)
const helpId = computed(() => `${controlId.value}-help`)
const errorId = computed(() => `${controlId.value}-error`)

const describedBy = computed(
  () =>
    [props.help ? helpId.value : '', props.error ? errorId.value : ''].filter(Boolean).join(' ') ||
    undefined,
)

// Bind with `<InputText v-bind="attrs" :invalid="invalid" />` (slot props `attrs`, `invalid`).
const attrs = computed(() => ({
  id: controlId.value,
  'aria-describedby': describedBy.value,
  'aria-invalid': props.error ? ('true' as const) : undefined,
  'aria-required': props.required ? ('true' as const) : undefined,
}))
</script>

<template>
  <div class="flex flex-col gap-1">
    <label :for="controlId" class="text-sm font-medium text-sk-text">
      {{ label }}
      <template v-if="required">
        <span aria-hidden="true" class="text-sk-danger"> *</span>
        <span class="sr-only"> ({{ t('common.required') }})</span>
      </template>
    </label>
    <slot :id="controlId" :attrs="attrs" :invalid="Boolean(error)" />
    <p v-if="help" :id="helpId" class="text-sm text-sk-muted">{{ help }}</p>
    <!-- Always rendered so the live region exists before the message appears. -->
    <p :id="errorId" aria-live="polite" class="text-sm text-sk-danger">
      <template v-if="error">
        <i class="ti ti-alert-circle" aria-hidden="true" />
        {{ error }}
      </template>
    </p>
  </div>
</template>
