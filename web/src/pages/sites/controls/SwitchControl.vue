<script setup lang="ts">
defineOptions({ inheritAttrs: false })

defineProps<{ modelValue?: boolean; label: string }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
</script>

<template>
  <label class="flex items-center gap-2">
    <input
      v-bind="$attrs"
      type="checkbox"
      :checked="modelValue === true"
      class="size-4 accent-[var(--sk-accent)]"
      @change="emit('update:modelValue', ($event.target as HTMLInputElement).checked)"
    />
    {{ label }}
  </label>
</template>
