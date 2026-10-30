<script setup lang="ts" generic="T">
import { computed, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import SkFormField from './SkFormField.vue'

/**
 * A form row for a policy value that may be inherited (global defaults -> site -> endpoint).
 *
 * v-model is the OVERRIDE: `undefined` means "not overridden, use the inherited value",
 * anything else (including `false`, `0` and `''`) is an explicit override. The parent
 * serialises `undefined` as an omitted field.
 *
 * Usage:
 *   <SkInheritedField v-model="form.rateLimit" :inherited="site.rate_limit" source="site" label="Rate limit">
 *     <template #default="{ attrs, value, update }">
 *       <InputNumber v-bind="attrs" :model-value="value" @update:model-value="update" />
 *     </template>
 *   </SkInheritedField>
 */
const props = defineProps<{
  label: string
  /** The override. `undefined` = inherited. */
  modelValue?: T
  /** The value that applies when not overridden. `undefined` = nothing set anywhere. */
  inherited?: T
  /** Where `inherited` comes from. */
  source?: 'defaults' | 'site' | 'builtin'
  /** Custom source text (already translated), overriding `source`. */
  sourceLabel?: string
  /** Initial override when the toggle is switched on; defaults to a copy of `inherited`. */
  defaultOverride?: T
  /** Renders the inherited value as text. Defaults to Yes/No, JSON for objects, String otherwise. */
  format?: (value: T) => string
  help?: string
  error?: string
  required?: boolean
  disabled?: boolean
}>()

const emit = defineEmits<{ 'update:modelValue': [value: T | undefined] }>()

const { t } = useI18n()
const uid = useId()
const toggleId = `inh-${uid}-toggle`
const sourceId = `inh-${uid}-source`

// A switched-on override with no value yet (nothing inherited to copy) must stay visible,
// so the toggle state is tracked separately from the model.
const overriding = ref(props.modelValue !== undefined)
watch(
  () => props.modelValue,
  (v) => {
    if (v !== undefined) overriding.value = true
    else overriding.value = false
  },
)

const sourceText = computed(
  () => props.sourceLabel ?? t(`common.inherited.source.${props.source ?? 'defaults'}`),
)

const inheritedText = computed(() => {
  if (props.inherited === undefined) return t('common.inherited.unset')
  if (props.format) return props.format(props.inherited)
  if (typeof props.inherited === 'boolean')
    return props.inherited ? t('common.yes') : t('common.no')
  if (typeof props.inherited === 'object' && props.inherited !== null)
    return JSON.stringify(props.inherited)
  return String(props.inherited)
})

// Values are JSON config; JSON round-tripping also copes with reactive proxies,
// which structuredClone rejects.
function clone(value: T | undefined): T | undefined {
  return value === undefined ? undefined : (JSON.parse(JSON.stringify(value)) as T)
}

function setOverride(on: boolean) {
  if (props.disabled) return
  overriding.value = on
  emit('update:modelValue', on ? clone(props.defaultOverride ?? props.inherited) : undefined)
}

function update(value: T | undefined) {
  emit('update:modelValue', value)
}
</script>

<template>
  <SkFormField :label="label" :help="help" :error="error" :required="required">
    <template #default="{ attrs }">
      <div
        class="flex flex-col gap-2 rounded-sk border border-sk-border p-3"
        :data-overridden="overriding"
      >
        <div class="flex flex-wrap items-center justify-between gap-2">
          <p :id="sourceId" class="flex items-center gap-1 text-sm text-sk-muted">
            <i
              :class="['ti', overriding ? 'ti-pencil' : 'ti-corner-left-down']"
              aria-hidden="true"
            />
            <template v-if="overriding">
              {{ t('common.inherited.overrides', { source: sourceText, value: inheritedText }) }}
            </template>
            <template v-else>{{ t('common.inherited.from', { source: sourceText }) }}</template>
          </p>
          <label :for="toggleId" class="flex items-center gap-2 text-sm font-medium">
            <input
              :id="toggleId"
              type="checkbox"
              role="switch"
              :checked="overriding"
              :disabled="disabled"
              :aria-describedby="sourceId"
              class="size-4 accent-[var(--sk-accent)]"
              @change="setOverride(($event.target as HTMLInputElement).checked)"
            />
            {{ t('common.inherited.override') }}
            <span class="sr-only">{{ label }}</span>
          </label>
        </div>

        <div v-if="overriding">
          <slot :attrs="attrs" :value="modelValue" :update="update" :disabled="disabled" />
        </div>
        <output
          v-else
          :id="attrs.id"
          :aria-describedby="attrs['aria-describedby']"
          class="block text-sk-muted"
          data-testid="inherited-value"
        >
          {{ inheritedText }}
        </output>
      </div>
    </template>
  </SkFormField>
</template>
