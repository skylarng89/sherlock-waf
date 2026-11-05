<script setup lang="ts">
import { ref, watch } from 'vue'
import { controlClass } from './classes'

defineOptions({ inheritAttrs: false })

const props = defineProps<{ modelValue?: string[]; rows?: number }>()
const emit = defineEmits<{ 'update:modelValue': [value: string[]] }>()

function parse(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '')
}

// The raw text is kept locally so a trailing newline survives while the user types.
const raw = ref((props.modelValue ?? []).join('\n'))
watch(
  () => props.modelValue,
  (value) => {
    if (JSON.stringify(parse(raw.value)) !== JSON.stringify(value ?? [])) {
      raw.value = (value ?? []).join('\n')
    }
  },
)

function onInput(event: Event) {
  raw.value = (event.target as HTMLTextAreaElement).value
  emit('update:modelValue', parse(raw.value))
}
</script>

<template>
  <textarea
    v-bind="$attrs"
    :value="raw"
    :rows="rows ?? 3"
    :class="[controlClass, 'font-mono']"
    autocapitalize="off"
    spellcheck="false"
    @input="onInput"
  />
</template>
