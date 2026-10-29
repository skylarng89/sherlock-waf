<script setup lang="ts">
import { useI18n } from 'vue-i18n'

defineProps<{ stale: boolean; precondition: boolean; unmatched: string[] }>()
const emit = defineEmits<{ reload: [] }>()

const { t } = useI18n()
</script>

<template>
  <div class="flex flex-col gap-3">
    <div
      v-if="stale || precondition"
      role="alert"
      class="flex flex-wrap items-center justify-between gap-2 rounded-sk border border-sk-warning bg-sk-warning-bg p-3 text-sk-warning"
    >
      <p>
        <i class="ti ti-refresh-alert" aria-hidden="true" />
        {{ stale ? t('common.errors.stale') : t('common.errors.preconditionRequired') }}
      </p>
      <button
        type="button"
        class="rounded-sk border border-current px-3 py-1 font-medium"
        @click="emit('reload')"
      >
        {{ t('common.actions.reload') }}
      </button>
    </div>
    <div
      v-if="unmatched.length"
      role="alert"
      class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
    >
      <p class="font-medium">
        <i class="ti ti-alert-circle" aria-hidden="true" />
        {{ t('sites.errors.summary') }}
      </p>
      <ul class="list-disc pl-6">
        <li v-for="m in unmatched" :key="m">{{ m }}</li>
      </ul>
    </div>
  </div>
</template>
