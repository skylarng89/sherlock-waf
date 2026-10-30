<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { RouterLink, useRoute } from 'vue-router'
import { useNavItems } from '@/composables/useNav'
import ThemeToggle from './ThemeToggle.vue'
import UserMenu from './UserMenu.vue'

const { t } = useI18n()
const route = useRoute()
const items = useNavItems()
const navOpen = ref(false)
const main = ref<HTMLElement>()
const menuButton = ref<HTMLButtonElement>()

function label(item: { labelKey?: string; label?: string }): string {
  return item.labelKey ? t(item.labelKey) : (item.label ?? '')
}

function focusMain() {
  const target = main.value?.querySelector<HTMLElement>('[data-page-title]') ?? main.value
  target?.focus()
}

// Move focus to the new page's heading so screen-reader and keyboard users land on it.
watch(
  () => route.path,
  async () => {
    navOpen.value = false
    await nextTick()
    focusMain()
  },
)

function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape' && navOpen.value) {
    navOpen.value = false
    menuButton.value?.focus()
  }
}
onMounted(() => document.addEventListener('keydown', onKeydown))
onBeforeUnmount(() => document.removeEventListener('keydown', onKeydown))
</script>

<template>
  <div
    class="min-h-screen bg-sk-bg text-sk-text lg:grid lg:grid-cols-[var(--sk-sidebar-width)_1fr]"
  >
    <a
      href="#main"
      class="sr-only z-50 rounded-sk bg-sk-surface px-4 py-2 text-sk-accent focus:not-sr-only focus:fixed focus:top-2 focus:left-2"
      @click.prevent="focusMain"
    >
      {{ t('nav.skipToContent') }}
    </a>

    <div
      :class="[
        'fixed inset-y-0 left-0 z-30 w-[var(--sk-sidebar-width)] border-r border-sk-border bg-sk-surface lg:static lg:block',
        navOpen ? 'block' : 'hidden',
      ]"
      data-testid="sidebar"
    >
      <p class="flex items-center gap-2 px-4 py-4 text-lg font-semibold">
        <i class="ti ti-shield-check text-sk-accent" aria-hidden="true" />
        {{ t('common.appName') }}
      </p>
      <nav id="primary-nav" :aria-label="t('nav.main')">
        <ul class="flex flex-col gap-0.5 px-2">
          <li v-for="item in items" :key="item.id">
            <RouterLink
              :to="item.to"
              :active-class="item.to === '/' ? '' : 'sk-nav-active'"
              exact-active-class="sk-nav-active"
              class="flex items-center gap-2 rounded-sk px-3 py-2 hover:bg-sk-surface-muted"
            >
              <i :class="item.icon" aria-hidden="true" />
              {{ label(item) }}
            </RouterLink>
          </li>
        </ul>
      </nav>
    </div>

    <div class="flex min-w-0 flex-col">
      <header class="flex items-center gap-3 border-b border-sk-border bg-sk-surface px-4 py-2">
        <button
          ref="menuButton"
          type="button"
          class="rounded-sk border border-sk-border-strong px-2 py-1.5 lg:hidden"
          :aria-expanded="navOpen"
          aria-controls="primary-nav"
          data-testid="nav-toggle"
          @click="navOpen = !navOpen"
        >
          <i class="ti ti-menu-2" aria-hidden="true" />
          <span class="sr-only">{{ navOpen ? t('nav.close') : t('nav.open') }}</span>
        </button>
        <span class="font-semibold lg:hidden">{{ t('common.appName') }}</span>
        <div class="ml-auto flex items-center gap-3">
          <ThemeToggle />
          <UserMenu />
        </div>
      </header>
      <main
        id="main"
        ref="main"
        tabindex="-1"
        class="min-w-0 flex-1 p-[var(--sk-space-page)] outline-none"
      >
        <slot />
      </main>
    </div>
  </div>
</template>
