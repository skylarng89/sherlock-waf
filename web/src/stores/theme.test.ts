import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it } from 'vitest'
import { useThemeStore } from './theme'

describe('theme store', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.classList.remove('dark')
    setActivePinia(createPinia())
  })

  it('defaults to light when nothing is stored and the OS does not prefer dark', () => {
    expect(useThemeStore().dark).toBe(false)
  })

  it('toggle flips the class on <html> and persists the choice', () => {
    const theme = useThemeStore()
    theme.toggle()
    expect(theme.dark).toBe(true)
    expect(document.documentElement.classList.contains('dark')).toBe(true)
    expect(localStorage.getItem('sherlock.theme')).toBe('dark')

    theme.toggle()
    expect(document.documentElement.classList.contains('dark')).toBe(false)
    expect(localStorage.getItem('sherlock.theme')).toBe('light')
  })

  it('restores the stored preference', () => {
    localStorage.setItem('sherlock.theme', 'dark')
    setActivePinia(createPinia())
    expect(useThemeStore().dark).toBe(true)
  })
})
