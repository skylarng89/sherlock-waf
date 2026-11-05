import { onBeforeUnmount, ref } from 'vue'

export function useReducedMotion() {
  const reduced = ref(false)
  const query =
    typeof window.matchMedia === 'function'
      ? window.matchMedia('(prefers-reduced-motion: reduce)')
      : undefined
  if (query) {
    reduced.value = query.matches
    const listener = (e: MediaQueryListEvent) => (reduced.value = e.matches)
    query.addEventListener('change', listener)
    onBeforeUnmount(() => query.removeEventListener('change', listener))
  }
  return reduced
}
