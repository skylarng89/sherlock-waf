<script setup lang="ts">
import Button from 'openvue/button'
import { computed, ref, useId } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import SkFormField from '@/components/SkFormField.vue'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import { sourceLabel } from '@/pages/sites/lib/layers'
import { effectiveAccess } from './effective'
import { HTTP_METHODS, matchSummary, rateLimitSummary } from './policy'

const props = defineProps<{ site: string; section: 'acl' | 'rate-limits' }>()
const { t } = useI18n()
const { client, call } = useApi()
const uid = useId()

const method = ref<string>('GET')
const path = ref('/')
const busy = ref(false)
const failure = ref<string>()
const result = ref<components['schemas']['EffectivePolicy']>()
const view = computed(() => (result.value ? effectiveAccess(result.value) : undefined))

async function run() {
  busy.value = true
  failure.value = undefined
  try {
    const res = await call(
      client.GET('/sites/{site}/effective-policy', {
        params: { path: { site: props.site }, query: { path: path.value, method: method.value } },
      }),
      { toast: false },
    )
    result.value = res.data
  } catch (e) {
    result.value = undefined
    failure.value = e instanceof ApiError ? (e.detail ?? e.title) : t('common.errors.unknown')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section class="rounded-sk border border-sk-border p-4" :aria-labelledby="`${uid}-title`">
    <h2 :id="`${uid}-title`" class="text-lg font-semibold">{{ t('access.tester.title') }}</h2>
    <p class="mb-4 text-sk-muted">{{ t('access.tester.description') }}</p>
    <form class="flex flex-wrap items-end gap-4" novalidate @submit.prevent="run">
      <SkFormField :label="t('sites.tester.method')">
        <template #default="{ attrs }">
          <SelectControl
            v-bind="attrs"
            v-model="method"
            :options="HTTP_METHODS.map((m) => ({ value: m, label: m }))"
          />
        </template>
      </SkFormField>
      <div class="min-w-48 flex-1">
        <SkFormField :label="t('sites.tester.path')">
          <template #default="{ attrs }">
            <TextControl v-bind="attrs" v-model="path" mono />
          </template>
        </SkFormField>
      </div>
      <div class="pb-6">
        <Button type="submit" :label="t('sites.tester.run')" :loading="busy" :disabled="busy" />
      </div>
    </form>

    <p v-if="failure" role="alert" class="mt-2 text-sk-danger">
      <i class="ti ti-alert-circle" aria-hidden="true" />
      {{ failure }}
    </p>

    <div v-if="view && result" class="mt-4 flex flex-col gap-4" role="status">
      <p data-testid="matched" class="font-medium">
        <template v-if="result.matched_endpoint">
          {{ t('sites.tester.matched', { id: result.matched_endpoint }) }}
        </template>
        <template v-else>{{ t('sites.tester.noMatch') }}</template>
      </p>

      <div
        v-if="section === 'acl'"
        class="overflow-x-auto"
        tabindex="0"
        role="region"
        :aria-label="t('access.tester.aclScroll')"
      >
        <table class="w-full text-left" data-testid="effective-acl">
          <caption class="text-left font-medium">
            {{
              t('access.tester.aclCaption')
            }}
          </caption>
          <thead>
            <tr class="border-b border-sk-border-strong">
              <th scope="col" class="p-2">{{ t('sites.tester.field') }}</th>
              <th scope="col" class="p-2">{{ t('sites.tester.value') }}</th>
              <th scope="col" class="p-2">{{ t('sites.tester.source') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in view.acl" :key="r.field" class="border-b border-sk-border">
              <th scope="row" class="p-2 font-mono text-sm font-normal">{{ r.field }}</th>
              <td class="p-2 font-mono text-sm">{{ r.value }}</td>
              <td class="p-2" :data-source="r.source">
                <i class="ti ti-corner-left-down" aria-hidden="true" />
                {{ sourceLabel(r.source) }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <template v-else>
        <div
          class="overflow-x-auto"
          tabindex="0"
          role="region"
          :aria-label="t('access.tester.limitsScroll')"
        >
          <table class="w-full text-left" data-testid="effective-limits">
            <caption class="text-left font-medium">
              {{
                t('access.tester.limitsCaption')
              }}
            </caption>
            <thead>
              <tr class="border-b border-sk-border-strong">
                <th scope="col" class="p-2">{{ t('access.rateLimits.cols.name') }}</th>
                <th scope="col" class="p-2">{{ t('access.rateLimits.cols.match') }}</th>
                <th scope="col" class="p-2">{{ t('access.rateLimits.cols.limit') }}</th>
                <th scope="col" class="p-2">{{ t('access.rateLimits.cols.action') }}</th>
                <th scope="col" class="p-2">{{ t('sites.tester.source') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="view.rateLimits.length === 0">
                <td colspan="5" class="p-2 text-sk-muted">{{ t('access.tester.noLimits') }}</td>
              </tr>
              <tr v-for="r in view.rateLimits" :key="r.field" class="border-b border-sk-border">
                <th scope="row" class="p-2 font-mono text-sm font-normal">{{ r.field }}</th>
                <td class="p-2 font-mono text-sm">{{ matchSummary(r.item) }}</td>
                <td class="p-2">{{ rateLimitSummary(r.item) }}</td>
                <td class="p-2">{{ t(`access.actions.${r.item.action ?? 'block'}`) }}</td>
                <td class="p-2" :data-source="r.source">
                  <i class="ti ti-corner-left-down" aria-hidden="true" />
                  {{ sourceLabel(r.source) }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div
          class="overflow-x-auto"
          tabindex="0"
          role="region"
          :aria-label="t('access.tester.autoBanScroll')"
        >
          <table class="w-full text-left" data-testid="effective-auto-ban">
            <caption class="text-left font-medium">
              {{
                t('access.tester.autoBanCaption')
              }}
            </caption>
            <tbody>
              <tr v-for="r in view.autoBan" :key="r.field" class="border-b border-sk-border">
                <th scope="row" class="p-2 font-mono text-sm font-normal">{{ r.field }}</th>
                <td class="p-2 font-mono text-sm">{{ r.value }}</td>
                <td class="p-2" :data-source="r.source">
                  <i class="ti ti-corner-left-down" aria-hidden="true" />
                  {{ sourceLabel(r.source) }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>
    </div>
  </section>
</template>
