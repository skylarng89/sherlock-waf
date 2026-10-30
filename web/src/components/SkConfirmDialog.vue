<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps<{
  open: boolean
  title: string
  message?: string
  confirmLabel?: string
  cancelLabel?: string
  /** Styles the confirm button as destructive. */
  danger?: boolean
  /** When set, the user must type exactly this string before Confirm is enabled. */
  confirmText?: string
  /** Disables both buttons while the action runs. */
  busy?: boolean
}>()

const emit = defineEmits<{
  'update:open': [value: boolean]
  confirm: []
  cancel: []
}>()

const { t } = useI18n()
const uid = useId()
const titleId = `dlg-${uid}-title`
const messageId = `dlg-${uid}-msg`
const inputId = `dlg-${uid}-input`

const dialog = ref<HTMLDialogElement>()
const input = ref<HTMLInputElement>()
const cancelButton = ref<HTMLButtonElement>()
const typed = ref('')
let opener: HTMLElement | null = null

const canConfirm = computed(
  () => !props.busy && (props.confirmText === undefined || typed.value === props.confirmText),
)

// A native <dialog> opened with showModal() provides the focus trap, inert background
// and Esc handling; we only add initial focus and focus return.
async function sync(open: boolean) {
  const el = dialog.value
  if (!el) return
  if (open && !el.open) {
    opener = document.activeElement instanceof HTMLElement ? document.activeElement : null
    typed.value = ''
    el.showModal()
    await nextTick()
    // Destructive prompts start on the safe choice, never on Confirm.
    ;(props.confirmText !== undefined ? input.value : cancelButton.value)?.focus()
  } else if (!open && el.open) {
    el.close()
    opener?.focus()
    opener = null
  }
}

watch(() => props.open, sync, { flush: 'post' })
onMounted(() => sync(props.open))
onBeforeUnmount(() => {
  if (dialog.value?.open) dialog.value.close()
})

function cancel() {
  emit('cancel')
  emit('update:open', false)
}

function onNativeCancel(e: Event) {
  // Esc: let our state drive closing so the v-model stays the source of truth.
  e.preventDefault()
  if (!props.busy) cancel()
}

function confirm() {
  if (canConfirm.value) emit('confirm')
}
</script>

<template>
  <dialog
    ref="dialog"
    :aria-labelledby="titleId"
    :aria-describedby="message ? messageId : undefined"
    class="m-auto w-[min(32rem,calc(100vw-2rem))] rounded-sk-lg border border-sk-border-strong bg-sk-surface p-6 text-sk-text backdrop:bg-black/50"
    @cancel="onNativeCancel"
  >
    <form method="dialog" class="flex flex-col gap-4" @submit.prevent="confirm">
      <h2 :id="titleId" class="text-lg font-semibold">{{ title }}</h2>
      <p v-if="message" :id="messageId" class="text-sk-muted">{{ message }}</p>
      <slot />
      <div v-if="confirmText !== undefined" class="flex flex-col gap-1">
        <label :for="inputId" class="text-sm font-medium">
          {{ t('common.confirm.typeToConfirm', { value: confirmText }) }}
        </label>
        <input
          :id="inputId"
          ref="input"
          v-model="typed"
          type="text"
          autocomplete="off"
          autocapitalize="off"
          spellcheck="false"
          class="rounded-sk border border-sk-border-strong bg-sk-surface px-3 py-2 font-mono"
        />
      </div>
      <div class="flex justify-end gap-2">
        <button
          ref="cancelButton"
          type="button"
          :disabled="busy"
          class="rounded-sk border border-sk-border-strong px-4 py-2 hover:bg-sk-surface-muted disabled:opacity-60"
          @click="cancel"
        >
          {{ cancelLabel ?? t('common.actions.cancel') }}
        </button>
        <button
          type="submit"
          :disabled="!canConfirm"
          :class="[
            'rounded-sk px-4 py-2 font-medium text-sk-accent-contrast disabled:cursor-not-allowed disabled:opacity-50',
            danger ? 'bg-sk-danger hover:opacity-90' : 'bg-sk-accent hover:bg-sk-accent-hover',
          ]"
        >
          {{ confirmLabel ?? t('common.actions.confirm') }}
        </button>
      </div>
    </form>
  </dialog>
</template>
