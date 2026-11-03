<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps<{
  open: boolean
  title: string
  submitLabel?: string
  /** Disables the buttons while the request runs. */
  busy?: boolean
}>()

const emit = defineEmits<{ 'update:open': [value: boolean]; submit: [] }>()

const { t } = useI18n()
const titleId = `dlg-${useId()}-title`
const dialog = ref<HTMLDialogElement>()
let opener: HTMLElement | null = null

// A modal <dialog> gives the focus trap, inert background and Esc; this adds initial
// focus on the first field and focus return to the control that opened it.
async function sync(open: boolean) {
  const el = dialog.value
  if (!el) return
  if (open && !el.open) {
    opener = document.activeElement instanceof HTMLElement ? document.activeElement : null
    el.showModal()
    await nextTick()
    el.querySelector<HTMLElement>('input:not([type=hidden]), select, textarea')?.focus()
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

function close() {
  if (!props.busy) emit('update:open', false)
}
</script>

<template>
  <dialog
    ref="dialog"
    :aria-labelledby="titleId"
    class="m-auto max-h-[calc(100vh-2rem)] w-[min(40rem,calc(100vw-2rem))] overflow-y-auto rounded-sk-lg border border-sk-border-strong bg-sk-surface p-6 text-sk-text backdrop:bg-black/50"
    @cancel.prevent="close"
  >
    <form class="flex flex-col gap-4" novalidate @submit.prevent="emit('submit')">
      <h2 :id="titleId" class="text-lg font-semibold">{{ title }}</h2>
      <slot />
      <div class="flex flex-wrap items-center justify-end gap-2">
        <slot name="footer-extra" />
        <button
          type="button"
          :disabled="busy"
          class="rounded-sk border border-sk-border-strong px-4 py-2 hover:bg-sk-surface-muted disabled:opacity-60"
          @click="close"
        >
          {{ t('common.actions.cancel') }}
        </button>
        <button
          type="submit"
          :disabled="busy"
          class="rounded-sk bg-sk-accent px-4 py-2 font-medium text-sk-accent-contrast hover:bg-sk-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
        >
          {{ submitLabel ?? t('common.actions.save') }}
        </button>
      </div>
    </form>
  </dialog>
</template>
