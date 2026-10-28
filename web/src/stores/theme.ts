import { defineStore } from 'pinia'
import { ref } from 'vue'

const STORAGE_KEY = 'sherlock.theme'

function readStoredDark(): boolean {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored !== null) return stored === 'dark'
  } catch {
    // Storage can be blocked; fall back to the OS preference.
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false
}

export const useThemeStore = defineStore('theme', () => {
  const dark = ref(readStoredDark())

  function apply() {
    document.documentElement.classList.toggle('dark', dark.value)
  }

  function toggle() {
    dark.value = !dark.value
    apply()
    try {
      localStorage.setItem(STORAGE_KEY, dark.value ? 'dark' : 'light')
    } catch {
      // Preference simply does not persist.
    }
  }

  return { dark, apply, toggle }
})
