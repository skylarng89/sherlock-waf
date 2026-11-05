<script setup lang="ts">
import { computed, ref, useId } from 'vue'
import { useI18n } from 'vue-i18n'
import { controlClass } from '@/pages/sites/controls/classes'

defineOptions({ inheritAttrs: false })

const props = defineProps<{
  modelValue: string[]
  /** Offered in the input's datalist. */
  suggestions?: string[]
  /** Accessible name of the add input when the surrounding label does not name it. */
  inputLabel?: string
  /** Accessible name of the chip list. */
  listLabel: string
  /** Applied to every entry before it is added, e.g. upper-casing country codes. */
  normalize?: (value: string) => string
  /** Returns a message when the entry must be refused. */
  validate?: (value: string) => string | undefined
  disabled?: boolean
}>()
const emit = defineEmits<{ 'update:modelValue': [value: string[]] }>()

const { t } = useI18n()
const uid = useId()
const listId = `chips-${uid}-datalist`
const draft = ref('')
const problem = ref('')

const options = computed(() =>
  (props.suggestions ?? []).filter((s) => !props.modelValue.includes(s)),
)

function add() {
  const value = props.normalize ? props.normalize(draft.value.trim()) : draft.value.trim()
  if (value === '') return
  const message = props.validate?.(value)
  if (message) {
    problem.value = message
    return
  }
  problem.value = ''
  draft.value = ''
  if (!props.modelValue.includes(value)) emit('update:modelValue', [...props.modelValue, value])
}

function remove(name: string) {
  emit(
    'update:modelValue',
    props.modelValue.filter((n) => n !== name),
  )
}
</script>

<template>
  <div class="flex flex-col gap-2">
    <ul class="flex flex-wrap gap-2" :aria-label="listLabel">
      <li v-if="modelValue.length === 0" class="text-sm text-sk-muted">{{ t('common.none') }}</li>
      <li
        v-for="name in modelValue"
        :key="name"
        class="inline-flex items-center gap-1 rounded-full border border-sk-border-strong bg-sk-surface-muted px-2 py-0.5 font-mono text-sm"
      >
        {{ name }}
        <button
          v-if="!disabled"
          type="button"
          class="inline-flex size-6 items-center justify-center rounded-full"
          :aria-label="t('access.chips.remove', { name })"
          @click="remove(name)"
        >
          <i class="ti ti-x" aria-hidden="true" />
        </button>
      </li>
    </ul>
    <div v-if="!disabled" class="flex flex-wrap items-start gap-2">
      <input
        v-bind="$attrs"
        v-model="draft"
        type="text"
        :list="listId"
        :aria-label="inputLabel"
        :class="[controlClass, 'min-w-40 flex-1 font-mono']"
        autocomplete="off"
        autocapitalize="off"
        spellcheck="false"
        @keydown.enter.prevent="add"
      />
      <button
        type="button"
        class="min-h-9 rounded-sk border border-sk-border-strong px-3 py-1 font-medium"
        @click="add"
      >
        {{ t('access.chips.add') }}
      </button>
      <datalist :id="listId">
        <option v-for="o in options" :key="o" :value="o" />
      </datalist>
    </div>
    <p v-if="problem" role="alert" class="text-sm text-sk-danger">
      <i class="ti ti-alert-circle" aria-hidden="true" />
      {{ problem }}
    </p>
  </div>
</template>
