<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import ThemeToggle from './ThemeToggle.vue'

const { t } = useI18n()
const route = useRoute()
const main = ref<HTMLElement>()
const width = computed(() => (route.meta.wide ? 'max-w-3xl' : 'max-w-md'))

// Moving between sign-in steps replaces the whole card; put focus on the new heading.
watch(
  () => route.path,
  async () => {
    await nextTick()
    main.value?.querySelector<HTMLElement>('[data-page-title]')?.focus()
  },
)
</script>

<template>
  <div class="flex min-h-screen flex-col bg-sk-bg text-sk-text">
    <a
      href="#main"
      class="sr-only z-50 rounded-sk bg-sk-surface px-4 py-2 text-sk-accent focus:not-sr-only focus:fixed focus:top-2 focus:left-2"
    >
      {{ t('nav.skipToContent') }}
    </a>
    <header class="flex items-center justify-between px-4 py-3">
      <p class="flex items-center gap-2 text-lg font-semibold">
        <i class="ti ti-shield-check text-sk-accent" aria-hidden="true" />
        {{ t('common.appName') }}
      </p>
      <ThemeToggle />
    </header>
    <main id="main" ref="main" class="mx-auto w-full flex-1 px-4 py-8" :class="width">
      <div class="rounded-sk-lg border border-sk-border bg-sk-surface p-6 shadow-sm">
        <slot />
      </div>
    </main>
  </div>
</template>
