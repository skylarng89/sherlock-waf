<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { parseDiff } from './diff'

const props = defineProps<{ diff?: unknown }>()
const { t } = useI18n()

const text = computed(() => {
  const d = parseDiff(props.diff)
  const parts: string[] = []
  if (d.global) parts.push(t('history.summary.global'))
  if (d.added.length) parts.push(t('history.summary.added', d.added.length))
  if (d.removed.length) parts.push(t('history.summary.removed', d.removed.length))
  if (d.changed.length) parts.push(t('history.summary.changed', d.changed.length))
  return parts.length ? parts.join(', ') : t('history.summary.none')
})
</script>

<template>
  <span>{{ text }}</span>
</template>
