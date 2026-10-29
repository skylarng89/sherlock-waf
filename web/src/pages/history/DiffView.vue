<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { isEmptyDiff, parseDiff } from './diff'

const props = defineProps<{ diff?: unknown }>()
const { t } = useI18n()
const parsed = computed(() => parseDiff(props.diff))
</script>

<template>
  <p v-if="isEmptyDiff(parsed)" class="text-sk-muted">{{ t('history.detail.diffNone') }}</p>
  <div v-else class="flex flex-col gap-4">
    <p v-if="parsed.global" class="flex items-center gap-2">
      <i class="ti ti-adjustments" aria-hidden="true" />
      {{ t('history.detail.globalChanged') }}
    </p>
    <section v-if="parsed.added.length" aria-labelledby="diff-added">
      <h3 id="diff-added" class="font-medium text-sk-success">
        <i class="ti ti-plus" aria-hidden="true" /> {{ t('history.detail.added') }}
      </h3>
      <ul class="ml-6 list-disc">
        <li v-for="s in parsed.added" :key="s">
          <code>{{ s }}</code>
        </li>
      </ul>
    </section>
    <section v-if="parsed.removed.length" aria-labelledby="diff-removed">
      <h3 id="diff-removed" class="font-medium text-sk-danger">
        <i class="ti ti-minus" aria-hidden="true" /> {{ t('history.detail.removed') }}
      </h3>
      <ul class="ml-6 list-disc">
        <li v-for="s in parsed.removed" :key="s">
          <code>{{ s }}</code>
        </li>
      </ul>
    </section>
    <section v-if="parsed.changed.length" aria-labelledby="diff-changed">
      <h3 id="diff-changed" class="font-medium text-sk-warning">
        <i class="ti ti-pencil" aria-hidden="true" /> {{ t('history.detail.changed') }}
      </h3>
      <ul class="ml-6 list-disc">
        <li v-for="c in parsed.changed" :key="c.site">
          <code>{{ c.site }}</code>
          <span>{{
            ': ' + t('history.detail.fields', { fields: c.fields.join(', ') || t('common.none') })
          }}</span>
        </li>
      </ul>
    </section>
  </div>
</template>
