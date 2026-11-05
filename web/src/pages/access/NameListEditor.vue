<script setup lang="ts">
import { computed, ref, useId } from 'vue'
import { useI18n } from 'vue-i18n'
import { applyNameList, isNameListEdit, type NameList } from './policy'
import NameChips from './NameChips.vue'

/**
 * Edits a NameList: an array replaces the inherited list, `{add, remove}` edits it.
 * Without anything to inherit only the replace form applies.
 */
const props = defineProps<{
  modelValue: NameList | undefined
  /** Names an IP list may take (the global ip_lists). */
  known: string[]
  /** What the level inherits; undefined when there is no parent level. */
  inheritedNames?: string[]
  attrs: Record<string, unknown>
  label: string
  disabled?: boolean
}>()
const emit = defineEmits<{ update: [value: NameList | undefined] }>()

const { t } = useI18n()
const uid = useId()
const canEdit = computed(() => props.inheritedNames !== undefined)
const mode = ref<'replace' | 'edit'>(isNameListEdit(props.modelValue) ? 'edit' : 'replace')

const names = computed(() => (Array.isArray(props.modelValue) ? props.modelValue : []))
const added = computed(() => (isNameListEdit(props.modelValue) ? (props.modelValue.add ?? []) : []))
const removed = computed(() =>
  isNameListEdit(props.modelValue) ? (props.modelValue.remove ?? []) : [],
)

function setMode(next: 'replace' | 'edit') {
  if (next === mode.value) return
  mode.value = next
  // Leaving edit mode keeps what the edit produced, so nothing the user chose is lost.
  if (next === 'replace')
    emit('update', applyNameList(props.inheritedNames ?? [], props.modelValue))
  else emit('update', {})
}

function setReplace(list: string[]) {
  emit('update', canEdit.value || list.length ? list : undefined)
}

function setEdit(patch: { add?: string[]; remove?: string[] }) {
  const next = { add: added.value, remove: removed.value, ...patch }
  emit('update', {
    ...(next.add.length ? { add: next.add } : {}),
    ...(next.remove.length ? { remove: next.remove } : {}),
  })
}
</script>

<template>
  <div class="flex flex-col gap-3">
    <fieldset v-if="canEdit" class="flex flex-wrap gap-4" :disabled="disabled">
      <legend class="mb-1 text-sm font-medium">{{ t('access.nameList.mode') }}</legend>
      <label class="flex items-center gap-2">
        <input
          type="radio"
          :name="`mode-${uid}`"
          value="replace"
          :checked="mode === 'replace'"
          class="size-4 accent-[var(--sk-accent)]"
          @change="setMode('replace')"
        />
        {{ t('access.nameList.replace') }}
      </label>
      <label class="flex items-center gap-2">
        <input
          type="radio"
          :name="`mode-${uid}`"
          value="edit"
          :checked="mode === 'edit'"
          class="size-4 accent-[var(--sk-accent)]"
          @change="setMode('edit')"
        />
        {{ t('access.nameList.edit') }}
      </label>
    </fieldset>

    <template v-if="mode === 'replace'">
      <p v-if="canEdit" class="text-sm text-sk-muted">{{ t('access.nameList.replaceHelp') }}</p>
      <NameChips
        v-bind="attrs"
        :model-value="names"
        :suggestions="known"
        :list-label="t('access.nameList.listLabel', { field: label })"
        :disabled="disabled"
        @update:model-value="setReplace"
      />
    </template>
    <template v-else>
      <p class="text-sm text-sk-muted">
        {{ t('access.nameList.editHelp') }}
        <span class="font-mono">{{ (inheritedNames ?? []).join(', ') || t('common.none') }}</span>
      </p>
      <div class="flex flex-col gap-1">
        <p class="text-sm font-medium">{{ t('access.nameList.add') }}</p>
        <NameChips
          v-bind="attrs"
          :model-value="added"
          :suggestions="known"
          :list-label="t('access.nameList.addedLabel', { field: label })"
          :disabled="disabled"
          @update:model-value="setEdit({ add: $event })"
        />
      </div>
      <div class="flex flex-col gap-1">
        <p class="text-sm font-medium">{{ t('access.nameList.remove') }}</p>
        <NameChips
          :model-value="removed"
          :suggestions="inheritedNames"
          :input-label="t('access.nameList.removeInput', { field: label })"
          :list-label="t('access.nameList.removedLabel', { field: label })"
          :disabled="disabled"
          @update:model-value="setEdit({ remove: $event })"
        />
      </div>
    </template>
  </div>
</template>
