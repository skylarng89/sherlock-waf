import { defineStore } from 'pinia'
import { computed, ref } from 'vue'

const STORAGE_KEY = 'sherlock.theme'

export type ThemePreference = 'light' | 'dark' | 'system'

function readStoredPreference(): ThemePreference {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored === 'light' || stored === 'dark' || stored === 'system') return stored
  } catch {
    // Storage can be blocked; fall back to following the OS.
  }
  return 'system'
}

function systemQuery(): MediaQueryList | undefined {
  return window.matchMedia?.('(prefers-color-scheme: dark)')
}

export const useThemeStore = defineStore('theme', () => {
  const preference = ref<ThemePreference>(readStoredPreference())
  const systemDark = ref(systemQuery()?.matches ?? false)
  /** The effective theme after resolving "system". */
  const dark = computed(() =>
    preference.value === 'system' ? systemDark.value : preference.value === 'dark',
  )

  function apply() {
    document.documentElement.classList.toggle('dark', dark.value)
  }

  function persist() {
    try {
      localStorage.setItem(STORAGE_KEY, preference.value)
    } catch {
      // Preference simply does not persist.
    }
  }

  function setPreference(next: ThemePreference) {
    preference.value = next
    apply()
    persist()
  }

  /** Flips the effective theme and stores it as an explicit choice. */
  function toggle() {
    setPreference(dark.value ? 'light' : 'dark')
  }

  /** Starts following OS changes while the preference is "system". Returns a stop function. */
  function watchSystem(): () => void {
    const query = systemQuery()
    if (!query) return () => {}
    const listener = (e: MediaQueryListEvent) => {
      systemDark.value = e.matches
      apply()
    }
    query.addEventListener('change', listener)
    return () => query.removeEventListener('change', listener)
  }

  return { preference, dark, apply, toggle, setPreference, watchSystem }
})
