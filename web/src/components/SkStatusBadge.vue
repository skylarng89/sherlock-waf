<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

export type SiteMode = 'detect' | 'block' | 'off'
export type HealthState = 'ok' | 'warn' | 'error'

// Colour is never the only signal: every variant carries an icon and a text label.
const props = defineProps<{
  /** Site enforcement mode. Takes precedence over `state` when both are given. */
  mode?: SiteMode
  state?: HealthState
  /** Overrides the default text, e.g. "Block (3 hosts)". */
  label?: string
}>()

const { t } = useI18n()

const variants = {
  detect: { icon: 'ti-eye', tone: 'info', key: 'common.status.mode.detect' },
  block: { icon: 'ti-shield-lock', tone: 'success', key: 'common.status.mode.block' },
  off: { icon: 'ti-power', tone: 'muted', key: 'common.status.mode.off' },
  ok: { icon: 'ti-circle-check', tone: 'success', key: 'common.status.state.ok' },
  warn: { icon: 'ti-alert-triangle', tone: 'warning', key: 'common.status.state.warn' },
  error: { icon: 'ti-circle-x', tone: 'danger', key: 'common.status.state.error' },
} as const

const tones = {
  info: 'bg-sk-info-bg text-sk-info',
  success: 'bg-sk-success-bg text-sk-success',
  warning: 'bg-sk-warning-bg text-sk-warning',
  danger: 'bg-sk-danger-bg text-sk-danger',
  muted: 'bg-sk-surface-muted text-sk-muted',
} as const

const variant = computed(() => variants[props.mode ?? props.state ?? 'off'])
</script>

<template>
  <span
    :class="[
      'inline-flex items-center gap-1 rounded-full border border-current/30 px-2 py-0.5 text-xs font-medium',
      tones[variant.tone],
    ]"
  >
    <i :class="['ti', variant.icon]" aria-hidden="true" />
    {{ label ?? t(variant.key) }}
  </span>
</template>
