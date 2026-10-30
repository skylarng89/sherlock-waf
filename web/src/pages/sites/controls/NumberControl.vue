<script setup lang="ts">
import { controlClass } from './classes'

defineOptions({ inheritAttrs: false })

defineProps<{ modelValue?: number }>()
const emit = defineEmits<{ 'update:modelValue': [value: number | undefined] }>()

function onInput(event: Event) {
  const raw = (event.target as HTMLInputElement).value
  emit('update:modelValue', raw === '' ? undefined : Number(raw))
}
</script>

<template>
  <input
    v-bind="$attrs"
    type="number"
    inputmode="numeric"
    :value="modelValue ?? ''"
    :class="controlClass"
    @input="onInput"
  />
</template>
