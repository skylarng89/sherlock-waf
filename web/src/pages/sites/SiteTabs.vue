<script setup lang="ts">
import { useI18n } from 'vue-i18n'

defineProps<{ site: string }>()
const { t } = useI18n()

const tabs = [
  { route: 'site-detail', label: 'sites.tabs.settings' },
  { route: 'site-endpoints', label: 'sites.tabs.endpoints' },
  { route: 'site-acl', label: 'access.tabs.acl' },
  { route: 'site-rate-limits', label: 'access.tabs.rateLimits' },
  { route: 'site-bot', label: 'bot.tab' },
  { route: 'site-api', label: 'api.tab' },
  { route: 'site-tuning', label: 'tuning.tabs.tuning' },
  { route: 'site-custom-rules', label: 'tuning.tabs.customRules' },
]
</script>

<template>
  <nav :aria-label="t('sites.tabs.label')" class="mb-6 border-b border-sk-border">
    <ul class="flex flex-wrap gap-4">
      <li v-for="tab in tabs" :key="tab.route">
        <RouterLink
          :to="{ name: tab.route, params: { site } }"
          class="inline-block border-b-2 border-transparent px-1 py-2"
          active-class=""
          exact-active-class="border-sk-accent font-semibold text-sk-accent"
        >
          {{ t(tab.label) }}
        </RouterLink>
      </li>
    </ul>
  </nav>
</template>
