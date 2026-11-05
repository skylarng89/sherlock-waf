<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { buildPreviewDocument } from './preview'

const props = defineProps<{ html: string }>()
const { t } = useI18n()
const srcdoc = computed(() => buildPreviewDocument(props.html))
</script>

<template>
  <p v-if="!html.trim()" class="text-sk-muted">{{ t('certificates.blockPages.previewEmpty') }}</p>
  <!-- An empty sandbox attribute: no scripts, no same-origin, no forms, no popups. -->
  <iframe
    v-else
    sandbox=""
    referrerpolicy="no-referrer"
    :srcdoc="srcdoc"
    :title="t('certificates.blockPages.previewTitle')"
    class="h-72 w-full rounded-sk border border-sk-border-strong bg-white"
  />
</template>
