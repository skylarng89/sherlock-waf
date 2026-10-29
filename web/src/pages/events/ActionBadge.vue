<script setup lang="ts">
import { useI18n } from 'vue-i18n'

defineProps<{ action: string }>()
const { t, te } = useI18n()

// Icon plus text: the action is never conveyed by colour alone.
const ICONS: Record<string, string> = {
  allow: 'ti-circle-check',
  log: 'ti-notes',
  challenge: 'ti-puzzle',
  block: 'ti-ban',
  ratelimit: 'ti-gauge',
  ban: 'ti-lock',
}
</script>

<template>
  <span
    class="inline-flex items-center gap-1 rounded-full border border-sk-border-strong bg-sk-surface-muted px-2 py-0.5 text-xs font-medium"
  >
    <i :class="['ti', ICONS[action] ?? 'ti-circle']" aria-hidden="true" />
    {{ te(`events.actions.${action}`) ? t(`events.actions.${action}`) : action }}
  </span>
</template>
