<script setup lang="ts">
import Button from 'openvue/button'
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { components } from '@/api/schema'
import { ApiError } from '@/api/errors'
import { useApi } from '@/api/useApi'
import SkFormField from '@/components/SkFormField.vue'
import SelectControl from './controls/SelectControl.vue'
import TextControl from './controls/TextControl.vue'
import { flatten, sourceLabel } from './lib/layers'

const props = defineProps<{ site: string }>()
const { t } = useI18n()
const { client, call } = useApi()

const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const
const method = ref<string>('GET')
const path = ref('/')
const busy = ref(false)
const failure = ref<string>()
const result = ref<components['schemas']['EffectivePolicy']>()

const rows = computed(() =>
  result.value
    ? flatten(result.value.policy).map(([field, value]) => ({
        field,
        value: Array.isArray(value)
          ? value.map((v) => (typeof v === 'object' ? JSON.stringify(v) : String(v))).join(', ')
          : String(value),
        source: result.value?.sources[field],
      }))
    : [],
)

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
  <section class="rounded-sk border border-sk-border p-4" :aria-labelledby="'tester-title'">
    <h2 id="tester-title" class="text-lg font-semibold">{{ t('sites.tester.title') }}</h2>
    <p class="mb-4 text-sk-muted">{{ t('sites.tester.description') }}</p>
    <form class="flex flex-wrap items-end gap-4" novalidate @submit.prevent="run">
      <SkFormField :label="t('sites.tester.method')">
        <template #default="{ attrs }">
          <SelectControl
            v-bind="attrs"
            v-model="method"
            :options="methods.map((m) => ({ value: m, label: m }))"
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

    <div v-if="result" class="mt-4" role="status">
      <p data-testid="matched" class="font-medium">
        <template v-if="result.matched_endpoint">
          {{ t('sites.tester.matched', { id: result.matched_endpoint }) }}
        </template>
        <template v-else>{{ t('sites.tester.noMatch') }}</template>
      </p>
      <div
        class="overflow-x-auto"
        tabindex="0"
        role="region"
        :aria-label="t('sites.tester.scroll')"
      >
        <table class="mt-2 w-full text-left">
          <caption class="sr-only">
            {{
              t('sites.tester.caption')
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
            <tr v-for="r in rows" :key="r.field" class="border-b border-sk-border">
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
    </div>
  </section>
</template>
