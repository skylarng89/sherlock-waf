<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import SkConfirmDialog from '@/components/SkConfirmDialog.vue'

defineProps<{ siteName: string; busy?: boolean }>()
const open = defineModel<boolean>('open', { required: true })
const emit = defineEmits<{ confirm: [] }>()

const { t } = useI18n()
</script>

<template>
  <SkConfirmDialog
    v-model:open="open"
    danger
    :busy="busy"
    :title="t('sites.block.title', { site: siteName })"
    :message="t('sites.block.message')"
    :confirm-label="t('sites.block.confirm')"
    @confirm="emit('confirm')"
  >
    <ul class="list-disc pl-6 text-sk-muted">
      <li>{{ t('sites.block.effect1') }}</li>
      <li>{{ t('sites.block.effect2') }}</li>
    </ul>
    <p class="text-sm text-sk-muted">
      <i class="ti ti-info-circle" aria-hidden="true" />
      {{ t('sites.block.hint') }}
    </p>
  </SkConfirmDialog>
</template>
