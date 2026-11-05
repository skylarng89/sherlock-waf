import { computed } from 'vue'
import { extensionNavItems } from '@/extensions'
import { builtinNav } from '@/routes'
import { useSessionStore } from '@/stores/session'

/** Sidebar items the current user may see: built-in plus extension items, sorted. */
export function useNavItems() {
  const session = useSessionStore()
  return computed(() =>
    [...builtinNav, ...extensionNavItems.value]
      .filter((item) => session.can(item.permission))
      .sort((a, b) => (a.order ?? 100) - (b.order ?? 100)),
  )
}
