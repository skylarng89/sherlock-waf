<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { Policy, PolicyLayer } from '@/pages/sites/lib/layers'
import AclForm from './AclForm.vue'
import AutoBanForm from './AutoBanForm.vue'
import RateLimitsForm from './RateLimitsForm.vue'

/**
 * ACL, rate limits and auto-ban as three fieldsets, for the pages that edit a whole policy
 * (global defaults and endpoints). Sites get them as separate tabs.
 */
defineProps<{
  layers?: PolicyLayer[]
  scope: 'defaults' | 'endpoint'
  known: string[]
  disabled?: boolean
  errorFor: (path: string) => string | undefined
}>()
const model = defineModel<Policy>({ required: true })
const { t } = useI18n()
</script>

<template>
  <div class="flex flex-col gap-8" data-testid="access-sections">
    <fieldset class="flex flex-col gap-4">
      <legend class="mb-2 text-lg font-semibold">{{ t('access.sections.acl') }}</legend>
      <AclForm
        v-model="model"
        :layers="layers"
        :known="known"
        :disabled="disabled"
        :error-for="errorFor"
      />
    </fieldset>
    <fieldset class="flex flex-col gap-4">
      <legend class="mb-2 text-lg font-semibold">{{ t('access.sections.rateLimits') }}</legend>
      <RateLimitsForm v-model="model" :layers="layers" :disabled="disabled" :error-for="errorFor" />
    </fieldset>
    <fieldset class="flex flex-col gap-4">
      <legend class="mb-2 text-lg font-semibold">{{ t('access.sections.autoBan') }}</legend>
      <AutoBanForm
        v-model="model"
        :layers="layers"
        :endpoint="scope === 'endpoint'"
        :disabled="disabled"
        :error-for="errorFor"
      />
    </fieldset>
  </div>
</template>
