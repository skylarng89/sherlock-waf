<script setup lang="ts">
import { useI18n } from 'vue-i18n'

export interface Breadcrumb {
  label: string
  /** Omit on the current page. */
  to?: string
}

defineProps<{
  title: string
  description?: string
  breadcrumbs?: Breadcrumb[]
}>()

const { t } = useI18n()
</script>

<template>
  <header class="mb-6">
    <nav v-if="breadcrumbs?.length" :aria-label="t('nav.breadcrumb')" class="mb-2 text-sm">
      <ol class="flex flex-wrap items-center gap-1 text-sk-muted">
        <li v-for="(crumb, i) in breadcrumbs" :key="i" class="flex items-center gap-1">
          <i v-if="i > 0" class="ti ti-chevron-right text-xs" aria-hidden="true" />
          <RouterLink
            v-if="crumb.to && i < breadcrumbs.length - 1"
            :to="crumb.to"
            class="rounded-sk-sm text-sk-accent underline-offset-2 hover:underline"
          >
            {{ crumb.label }}
          </RouterLink>
          <span v-else aria-current="page">{{ crumb.label }}</span>
        </li>
      </ol>
    </nav>
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div class="min-w-0">
        <!-- tabindex -1: the shell moves focus here after each navigation. -->
        <h1 data-page-title tabindex="-1" class="text-2xl font-semibold text-sk-text outline-none">
          {{ title }}
        </h1>
        <p v-if="description" class="mt-1 text-sk-muted">{{ description }}</p>
      </div>
      <div v-if="$slots.actions" class="flex flex-wrap items-center gap-2">
        <slot name="actions" />
      </div>
    </div>
  </header>
</template>
