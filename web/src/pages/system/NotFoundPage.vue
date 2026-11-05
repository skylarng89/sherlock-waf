<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import SkPageHeader from '@/components/SkPageHeader.vue'

const { t } = useI18n()
</script>

<template>
  <SkPageHeader
    :title="t('common.notFoundPage.title')"
    :description="t('common.notFoundPage.body')"
  />
  <RouterLink :to="{ name: 'overview' }" class="text-sk-accent underline">
    {{ t('common.notFoundPage.home') }}
  </RouterLink>
</template>
