<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'

const { t } = useI18n()
const { client, call } = useApi()
const summary = ref<components['schemas']['VirtualPatchSummary']>()

onMounted(async () => {
  try {
    const res = await call(client.GET('/virtual-patches', { params: { query: { days: 7 } } }), {
      toast: false,
    })
    summary.value = res.data.summary
  } catch (e) {
    // The tile is optional; the rest of the overview does not depend on it.
    if (!isApiError(e)) throw e
  }
})
</script>

<template>
  <section
    v-if="summary"
    aria-labelledby="card-cves"
    class="rounded-sk-lg border border-sk-border bg-sk-surface p-4"
    data-testid="covered-cves"
  >
    <h2 id="card-cves" class="text-sm font-medium text-sk-muted">
      {{ t('tuning.coveredCves.title') }}
    </h2>
    <p class="text-2xl font-semibold" data-testid="covered-total">
      {{ t('tuning.coveredCves.total', { n: summary.cves_with_rule + summary.covered_cves }) }}
    </p>
    <ul class="mt-1 text-sm">
      <li>
        {{
          t('tuning.coveredCves.breakdown', {
            rules: summary.cves_with_rule,
            crs: summary.covered_cves,
          })
        }}
      </li>
      <li>{{ t('tuning.coveredCves.kev', { n: summary.kev_cves }) }}</li>
      <li>{{ t('tuning.coveredCves.sites', { n: summary.sites_protected }) }}</li>
      <li>{{ t('tuning.coveredCves.hits', { n: summary.hits }) }}</li>
    </ul>
    <RouterLink to="/virtual-patches" class="mt-2 inline-block text-sk-accent underline">
      {{ t('tuning.coveredCves.link') }}
    </RouterLink>
  </section>
</template>
