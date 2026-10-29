<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const STEPS = ['admin', 'hostname', 'site', 'done'] as const

const props = defineProps<{ current: 1 | 2 | 3 | 4 }>()
const { t } = useI18n()

const currentName = computed(() => t(`setup.steps.${STEPS[props.current - 1]}`))
</script>

<template>
  <nav :aria-label="t('setup.steps.label')" class="mb-6">
    <ol class="flex flex-wrap gap-x-6 gap-y-2">
      <li
        v-for="(step, i) in STEPS"
        :key="step"
        :aria-current="i + 1 === current ? 'step' : undefined"
        class="flex items-center gap-2"
        :class="i + 1 === current ? 'font-semibold text-sk-accent' : 'text-sk-muted'"
      >
        <i
          :class="[
            'ti',
            i + 1 < current ? 'ti-circle-check' : i + 1 === current ? 'ti-circle-dot' : 'ti-circle',
          ]"
          aria-hidden="true"
        />
        <span>{{ i + 1 }}. {{ t(`setup.steps.${step}`) }}</span>
        <span class="sr-only">
          {{
            i + 1 < current
              ? t('setup.steps.completed')
              : i + 1 === current
                ? t('setup.steps.currentState')
                : t('setup.steps.upcoming')
          }}
        </span>
      </li>
    </ol>
    <!-- Announced when the step changes; the visible list alone is silent. -->
    <p class="sr-only" role="status">
      {{ t('setup.steps.announce', { current, total: STEPS.length, name: currentName }) }}
    </p>
  </nav>
</template>
