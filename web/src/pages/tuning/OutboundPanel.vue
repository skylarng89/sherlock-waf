<script setup lang="ts">
import Button from 'openvue/button'
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import SkFormField from '@/components/SkFormField.vue'
import ListControl from '@/pages/sites/controls/ListControl.vue'
import NumberControl from '@/pages/sites/controls/NumberControl.vue'
import SwitchControl from '@/pages/sites/controls/SwitchControl.vue'
import type { components } from '@/api/schema'

type Waf = components['schemas']['WAFPolicy']

const props = defineProps<{
  waf: Waf | undefined
  canWrite: boolean
  busy: boolean
  save: (waf: Record<string, unknown>) => Promise<boolean>
}>()

const { t } = useI18n()
const enabled = ref(props.waf?.outbound_inspection ?? false)
const maxBytes = ref<number | undefined>(props.waf?.outbound_max_body_bytes)
const types = ref<string[]>(props.waf?.outbound_content_types ?? [])

watch(
  () => props.waf,
  (w) => {
    enabled.value = w?.outbound_inspection ?? false
    maxBytes.value = w?.outbound_max_body_bytes
    types.value = w?.outbound_content_types ?? []
  },
)

function submit() {
  void props.save({
    outbound_inspection: enabled.value,
    outbound_max_body_bytes: maxBytes.value ?? null,
    outbound_content_types: types.value.length ? types.value : null,
  })
}
</script>

<template>
  <section aria-labelledby="tn-outbound" class="rounded-sk-lg border border-sk-border p-4">
    <h2 id="tn-outbound" class="mb-1 text-lg font-semibold">{{ t('tuning.outbound.title') }}</h2>
    <p class="mb-3 text-sk-muted">{{ t('tuning.outbound.help') }}</p>
    <p v-if="!canWrite" class="mb-3 text-sk-muted">
      <i class="ti ti-lock" aria-hidden="true" /> {{ t('tuning.outbound.readOnly') }}
    </p>
    <form class="flex flex-col gap-4" novalidate @submit.prevent="submit">
      <SwitchControl
        v-model="enabled"
        :label="t('tuning.outbound.enabled')"
        :disabled="!canWrite"
      />
      <SkFormField
        :label="t('tuning.outbound.maxBody.label')"
        :help="t('tuning.outbound.maxBody.help')"
      >
        <template #default="{ attrs }">
          <NumberControl
            v-bind="attrs"
            v-model="maxBytes"
            :min="0"
            :disabled="!canWrite || !enabled"
          />
        </template>
      </SkFormField>
      <SkFormField
        :label="t('tuning.outbound.contentTypes.label')"
        :help="t('tuning.outbound.contentTypes.help')"
      >
        <template #default="{ attrs }">
          <ListControl v-bind="attrs" v-model="types" :disabled="!canWrite || !enabled" />
        </template>
      </SkFormField>
      <div v-if="canWrite">
        <Button type="submit" :label="t('tuning.outbound.save')" :disabled="busy" :loading="busy" />
      </div>
    </form>
  </section>
</template>
