<script setup lang="ts" generic="T extends string">
import { controlClass } from './classes'

defineOptions({ inheritAttrs: false })

defineProps<{
  modelValue?: T
  options: { value: T; label: string }[]
  /** Label of an extra first option that clears the value. */
  emptyLabel?: string
}>()
const emit = defineEmits<{ 'update:modelValue': [value: T | undefined] }>()

function onChange(event: Event) {
  const raw = (event.target as HTMLSelectElement).value
  emit('update:modelValue', raw === '' ? undefined : (raw as T))
}
</script>

<template>
  <select v-bind="$attrs" :value="modelValue ?? ''" :class="controlClass" @change="onChange">
    <option v-if="emptyLabel !== undefined" value="">{{ emptyLabel }}</option>
    <option v-for="o in options" :key="o.value" :value="o.value">{{ o.label }}</option>
  </select>
</template>
