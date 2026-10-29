import { createPinia, setActivePinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useThemeStore } from './theme'

describe('theme store', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.classList.remove('dark')
    setActivePinia(createPinia())
  })
  afterEach(() => vi.restoreAllMocks())

  it('defaults to light when nothing is stored and the OS does not prefer dark', () => {
    const theme = useThemeStore()
    expect(theme.dark).toBe(false)
    expect(theme.preference).toBe('system')
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

  it('supports an explicit system preference that is stored', () => {
    const theme = useThemeStore()
    theme.setPreference('dark')
    theme.setPreference('system')
    expect(localStorage.getItem('sherlock.theme')).toBe('system')
    expect(theme.dark).toBe(false)
  })

  it('ignores an unknown stored value', () => {
    localStorage.setItem('sherlock.theme', 'neon')
    setActivePinia(createPinia())
    expect(useThemeStore().preference).toBe('system')
  })

  it('follows the OS while the preference is system, and stops following when explicit', () => {
    let listener: ((e: MediaQueryListEvent) => void) | undefined
    vi.spyOn(window, 'matchMedia').mockReturnValue({
      matches: false,
      addEventListener: (_: string, l: (e: MediaQueryListEvent) => void) => (listener = l),
      removeEventListener: () => {},
    } as unknown as MediaQueryList)
    setActivePinia(createPinia())
    const theme = useThemeStore()
    theme.watchSystem()

    listener?.({ matches: true } as MediaQueryListEvent)
    expect(theme.dark).toBe(true)
    expect(document.documentElement.classList.contains('dark')).toBe(true)

    theme.setPreference('light')
    listener?.({ matches: true } as MediaQueryListEvent)
    expect(theme.dark).toBe(false)
  })
})
