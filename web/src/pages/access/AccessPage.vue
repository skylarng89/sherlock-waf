<script setup lang="ts">
import Button from 'openvue/button'
import { computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import SkPageHeader from '@/components/SkPageHeader.vue'
import { useSessionStore } from '@/stores/session'
import FeedsSection from './FeedsSection.vue'
import IpListsSection from './IpListsSection.vue'
import { useGlobalConfig } from './useGlobalConfig'

const { t } = useI18n()
const session = useSessionStore()
const store = useGlobalConfig()
const canWrite = computed(() => session.can('config:write'))

onMounted(store.load)
</script>

<template>
  <SkPageHeader :title="t('access.title')" :description="t('access.description')" />

  <p v-if="store.state.value === 'loading'" role="status">{{ t('common.loading') }}…</p>
  <div
    v-else-if="store.state.value === 'error'"
    role="alert"
    class="rounded-sk border border-sk-danger bg-sk-danger-bg p-3 text-sk-danger"
  >
    <p>
      <i class="ti ti-alert-circle" aria-hidden="true" />
      {{ t('access.loadFailed') }}
    </p>
    <Button :label="t('common.actions.retry')" severity="secondary" @click="store.load" />
  </div>
  <div v-else class="flex flex-col gap-10">
    <p v-if="!canWrite" role="status" class="text-sk-muted">
      <i class="ti ti-lock" aria-hidden="true" />
      {{ t('access.readOnly') }}
    </p>
    <IpListsSection :store="store" :can-write="canWrite" />
    <FeedsSection :store="store" :can-write="canWrite" />
  </div>
</template>
