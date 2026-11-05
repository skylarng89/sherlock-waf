<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import SelectControl from '@/pages/sites/controls/SelectControl.vue'
import SwitchControl from '@/pages/sites/controls/SwitchControl.vue'
import type { AclPolicy } from './policy'

type Reputation = NonNullable<AclPolicy['reputation']>

const props = defineProps<{
  modelValue: Reputation | undefined
  attrs: Record<string, unknown>
  disabled?: boolean
}>()
const emit = defineEmits<{ update: [value: Reputation] }>()

const { t } = useI18n()

function set(patch: Reputation) {
  emit('update', { enabled: true, action: 'block', ...props.modelValue, ...patch })
}
</script>

<template>
  <div class="flex flex-wrap items-end gap-4">
    <SwitchControl
      v-bind="attrs"
      :model-value="modelValue?.enabled ?? true"
      :label="t('access.acl.reputation.enabled')"
      :disabled="disabled"
      @update:model-value="set({ enabled: $event })"
    />
    <div class="flex flex-col gap-1">
      <label :for="`${String(attrs.id)}-action`" class="text-sm font-medium">
        {{ t('access.acl.reputation.action') }}
      </label>
      <SelectControl
        :id="`${String(attrs.id)}-action`"
        :model-value="modelValue?.action ?? 'block'"
        :options="
          (['block', 'log'] as const).map((a) => ({
            value: a,
            label: t(`access.actions.${a}`),
          }))
        "
        :disabled="disabled"
        @update:model-value="set({ action: $event ?? 'block' })"
      />
    </div>
  </div>
</template>
