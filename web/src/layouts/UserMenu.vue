<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, useId } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { useSessionStore } from '@/stores/session'

const { t } = useI18n()
const session = useSessionStore()
const router = useRouter()
const open = ref(false)
const root = ref<HTMLElement>()
const trigger = ref<HTMLButtonElement>()
const panelId = `user-menu-${useId()}`

function close(returnFocus = false) {
  open.value = false
  if (returnFocus) void nextTick(() => trigger.value?.focus())
}

function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape' && open.value) close(true)
}

function onPointerDown(e: Event) {
  if (open.value && root.value && !root.value.contains(e.target as Node)) close()
}

async function signOut() {
  close()
  await session.logout()
  await router.replace({ name: 'login' })
}

onMounted(() => {
  document.addEventListener('keydown', onKeydown)
  document.addEventListener('pointerdown', onPointerDown)
})
onBeforeUnmount(() => {
  document.removeEventListener('keydown', onKeydown)
  document.removeEventListener('pointerdown', onPointerDown)
})
</script>

<template>
  <div v-if="session.me" ref="root" class="relative">
    <button
      ref="trigger"
      type="button"
      :aria-expanded="open"
      :aria-controls="panelId"
      class="flex items-center gap-2 rounded-sk border border-sk-border-strong px-3 py-1.5 hover:bg-sk-surface-muted"
      data-testid="user-menu"
      @click="open = !open"
    >
      <i class="ti ti-user-circle" aria-hidden="true" />
      <span class="max-w-32 truncate">{{ session.me.username }}</span>
      <span class="sr-only">{{ t('nav.user.menu') }}</span>
      <i class="ti ti-chevron-down text-xs" aria-hidden="true" />
    </button>
    <div
      v-show="open"
      :id="panelId"
      class="absolute right-0 z-40 mt-1 w-56 rounded-sk border border-sk-border-strong bg-sk-surface p-2 shadow-lg"
    >
      <p class="px-2 py-1 text-sm text-sk-muted">
        {{ t('nav.user.signedInAs', { name: session.me.username }) }}<br />
        {{ t('nav.user.role', { role: session.me.role }) }}
      </p>
      <button
        type="button"
        class="mt-1 flex w-full items-center gap-2 rounded-sk-sm px-2 py-2 text-left hover:bg-sk-surface-muted"
        data-testid="sign-out"
        @click="signOut"
      >
        <i class="ti ti-logout" aria-hidden="true" />
        {{ t('nav.user.signOut') }}
      </button>
    </div>
  </div>
</template>
