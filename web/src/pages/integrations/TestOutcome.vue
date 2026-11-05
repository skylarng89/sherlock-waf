<script setup lang="ts">
import { useI18n } from 'vue-i18n'

defineProps<{ result?: { ok: boolean; error?: string }; testing?: boolean }>()
const { t } = useI18n()
</script>

<template>
  <!-- Always rendered so the live region exists before the result appears. -->
  <p role="status" aria-live="polite" class="text-sm" data-testid="test-outcome">
    <template v-if="testing">{{ t('integrations.test.running') }}…</template>
    <span v-else-if="result?.ok" class="text-sk-success">
      <i class="ti ti-circle-check" aria-hidden="true" />
      {{ t('integrations.test.ok') }}
    </span>
    <span v-else-if="result" class="text-sk-danger">
      <i class="ti ti-circle-x" aria-hidden="true" />
      {{
        result.error
          ? `${t('integrations.test.failed')}: ${result.error}`
          : t('integrations.test.failed')
      }}
    </span>
  </p>
</template>
