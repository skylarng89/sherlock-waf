<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { useToastStore } from '@/stores/toasts'

const { t } = useI18n()
const toasts = useToastStore()

const icons = {
  error: 'ti-alert-circle',
  success: 'ti-circle-check',
  info: 'ti-info-circle',
} as const
const tones = {
  error: 'border-sk-danger text-sk-danger',
  success: 'border-sk-success text-sk-success',
  info: 'border-sk-info text-sk-info',
} as const
</script>

<template>
  <section
    :aria-label="t('common.notice.region')"
    class="pointer-events-none fixed right-4 bottom-4 z-50 flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2"
  >
    <!-- Errors use role=alert (assertive); confirmations use role=status (polite). -->
    <div
      v-for="toast in toasts.items"
      :key="toast.id"
      :role="toast.kind === 'error' ? 'alert' : 'status'"
      :class="[
        'pointer-events-auto flex items-start gap-3 rounded-sk border-l-4 bg-sk-surface p-3 shadow-lg ring-1 ring-sk-border',
        tones[toast.kind],
      ]"
    >
      <i :class="['ti mt-0.5', icons[toast.kind]]" aria-hidden="true" />
      <div class="min-w-0 flex-1 text-sk-text">
        <p>{{ toast.message }}</p>
        <p v-if="toast.requestId" class="mt-1 text-xs text-sk-muted">
          {{ t('common.errors.requestId', { id: toast.requestId }) }}
        </p>
      </div>
      <button
        type="button"
        class="rounded-sk-sm p-1 text-sk-muted hover:text-sk-text"
        :aria-label="t('common.notice.dismiss')"
        @click="toasts.dismiss(toast.id)"
      >
        <i class="ti ti-x" aria-hidden="true" />
      </button>
    </div>
  </section>
</template>
