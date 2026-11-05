<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import NumberControl from '@/pages/sites/controls/NumberControl.vue'
import SwitchControl from '@/pages/sites/controls/SwitchControl.vue'
import TextControl from '@/pages/sites/controls/TextControl.vue'
import { getAt, setAt, type JsonObject } from '@/pages/sites/lib/json'
import { resolveInherited, type Policy, type PolicyLayer } from '@/pages/sites/lib/layers'
import PolicyRow from './PolicyRow.vue'

const FIELDS = [
  { key: 'enabled', kind: 'switch' },
  { key: 'blocks_threshold', kind: 'number' },
  { key: 'window', kind: 'text' },
  { key: 'ban_duration', kind: 'text' },
] as const

const props = defineProps<{
  layers?: PolicyLayer[]
  /** Endpoint values are ignored by the data plane: say so instead of offering fields. */
  endpoint?: boolean
  disabled?: boolean
  errorFor: (path: string) => string | undefined
}>()
const model = defineModel<Policy>({ required: true })
const { t } = useI18n()

function set(key: string, value: unknown) {
  model.value = setAt(model.value as JsonObject, `auto_ban.${key}`, value) as Policy
}
const resolved = (key: string) => resolveInherited(props.layers ?? [], `auto_ban.${key}`)
</script>

<template>
  <div class="flex flex-col gap-4" data-testid="auto-ban-form">
    <p class="rounded-sk border border-sk-border bg-sk-surface-muted p-3 text-sm">
      <i class="ti ti-info-circle" aria-hidden="true" />
      {{ t('access.autoBan.perSite') }}
    </p>
    <p v-if="errorFor('auto_ban')" role="alert" class="text-sk-danger">
      {{ errorFor('auto_ban') }}
    </p>
    <template v-if="!endpoint">
      <PolicyRow
        v-for="f in FIELDS"
        :key="f.key"
        :model-value="getAt(model, `auto_ban.${f.key}`)"
        :inheritable="layers !== undefined"
        :inherited="resolved(f.key).value"
        :source-label="resolved(f.key).label"
        :format="
          (v) => (typeof v === 'boolean' ? (v ? t('common.yes') : t('common.no')) : String(v))
        "
        :label="t(`access.autoBan.${f.key}.label`)"
        :help="t(`access.autoBan.${f.key}.help`)"
        :error="errorFor(`auto_ban.${f.key}`)"
        :disabled="disabled"
        @update:model-value="set(f.key, $event)"
      >
        <template #default="{ attrs, value, update, disabled: off, invalid }">
          <SwitchControl
            v-if="f.kind === 'switch'"
            v-bind="attrs"
            :model-value="typeof value === 'boolean' ? value : undefined"
            :label="t('access.autoBan.enabled.switch')"
            :disabled="off"
            @update:model-value="update"
          />
          <NumberControl
            v-else-if="f.kind === 'number'"
            v-bind="attrs"
            :min="1"
            :model-value="typeof value === 'number' ? value : undefined"
            :disabled="off"
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="update"
          />
          <TextControl
            v-else
            v-bind="attrs"
            mono
            :model-value="typeof value === 'string' ? value : undefined"
            :disabled="off"
            :aria-invalid="invalid ? 'true' : undefined"
            @update:model-value="update"
          />
        </template>
      </PolicyRow>
    </template>
  </div>
</template>
