<script setup lang="ts">
defineProps<{
  title: string
  description?: string
  /** Tabler icon classes, e.g. `ti ti-world`. Decorative. */
  icon?: string
}>()
</script>

<template>
  <section
    class="flex flex-col items-center gap-2 rounded-sk-lg border border-dashed border-sk-border-strong bg-sk-surface px-6 py-10 text-center"
  >
    <i v-if="icon" :class="[icon, 'text-3xl text-sk-muted']" aria-hidden="true" />
    <h2 class="text-lg font-medium text-sk-text">{{ title }}</h2>
    <p v-if="description" class="max-w-prose text-sk-muted">{{ description }}</p>
    <div v-if="$slots.default" class="mt-3 flex flex-wrap justify-center gap-2">
      <slot />
    </div>
  </section>
</template>
