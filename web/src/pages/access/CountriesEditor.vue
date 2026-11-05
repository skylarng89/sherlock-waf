<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import NameChips from './NameChips.vue'
import { COUNTRY_PATTERN, type AclPolicy } from './policy'

type Countries = NonNullable<AclPolicy['countries']>

const props = defineProps<{
  modelValue: Countries | undefined
  attrs: Record<string, unknown>
  label: string
  disabled?: boolean
}>()
const emit = defineEmits<{ update: [value: Countries] }>()

const { t } = useI18n()
const mode = computed(() => props.modelValue?.mode ?? 'off')
const list = computed(() => props.modelValue?.list ?? [])

function set(patch: Partial<Countries>) {
  const next = { mode: mode.value, list: list.value, ...patch }
  emit('update', { mode: next.mode, ...(next.list.length ? { list: next.list } : {}) })
}

function validate(code: string): string | undefined {
  return COUNTRY_PATTERN.test(code) ? undefined : t('access.acl.countries.invalid', { code })
}
</script>

<template>
  <div class="flex flex-col gap-3">
    <div class="flex flex-col gap-1">
      <label :for="String(attrs.id)" class="text-sm font-medium">
        {{ t('access.acl.countries.mode') }}
      </label>
      <SelectControl
        v-bind="attrs"
        :model-value="mode"
        :options="
          (['off', 'allow', 'deny'] as const).map((m) => ({
            value: m,
            label: t(`access.acl.countries.modes.${m}`),
          }))
        "
        :disabled="disabled"
        @update:model-value="set({ mode: $event ?? 'off' })"
      />
    </div>
    <div v-if="mode !== 'off'" class="flex flex-col gap-1">
      <p class="text-sm font-medium">{{ t('access.acl.countries.list') }}</p>
      <NameChips
        :model-value="list"
        :normalize="(v) => v.toUpperCase()"
        :validate="validate"
        :input-label="t('access.acl.countries.addInput')"
        :list-label="t('access.acl.countries.listLabel')"
        :disabled="disabled"
        @update:model-value="set({ list: $event })"
      />
      <p v-if="mode === 'allow' && list.length === 0" role="status" class="text-sm text-sk-warning">
        <i class="ti ti-alert-triangle" aria-hidden="true" />
        {{ t('access.acl.countries.emptyAllow') }}
      </p>
    </div>
  </div>
</template>
