<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { useThemeStore, type ThemePreference } from '@/stores/theme'

const { t } = useI18n()
const theme = useThemeStore()

const options: { value: ThemePreference; icon: string }[] = [
  { value: 'light', icon: 'ti-sun' },
  { value: 'dark', icon: 'ti-moon' },
  { value: 'system', icon: 'ti-device-desktop' },
]
</script>

<template>
  <div
    role="group"
    :aria-label="t('nav.theme.label')"
    class="flex rounded-sk border border-sk-border-strong"
  >
    <button
      v-for="o in options"
      :key="o.value"
      type="button"
      :aria-pressed="theme.preference === o.value"
      :data-testid="`theme-${o.value}`"
      :class="[
        'flex items-center px-2 py-1.5 first:rounded-l-[calc(var(--sk-radius)-1px)] last:rounded-r-[calc(var(--sk-radius)-1px)]',
        theme.preference === o.value
          ? 'bg-sk-accent text-sk-accent-contrast'
          : 'text-sk-text hover:bg-sk-surface-muted',
      ]"
      @click="theme.setPreference(o.value)"
    >
      <i :class="['ti', o.icon]" aria-hidden="true" />
      <span class="sr-only">{{ t(`nav.theme.${o.value}`) }}</span>
    </button>
  </div>
</template>
