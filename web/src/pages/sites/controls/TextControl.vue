<script setup lang="ts">
import { controlClass } from './classes'

defineOptions({ inheritAttrs: false })

defineProps<{ modelValue?: string; mono?: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [value: string] }>()
</script>

<template>
  <input
    v-bind="$attrs"
    type="text"
    :value="modelValue ?? ''"
    :class="[controlClass, mono ? 'font-mono' : '']"
    autocomplete="off"
    autocapitalize="off"
    spellcheck="false"
    @input="emit('update:modelValue', ($event.target as HTMLInputElement).value)"
  />
</template>
