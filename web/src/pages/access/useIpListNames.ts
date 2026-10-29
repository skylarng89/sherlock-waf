import { ref } from 'vue'
import { useApi } from '@/api/useApi'

/** Names of the global IP lists, for the pickers. A failure leaves the list empty: names can still be typed. */
export function useIpListNames() {
  const { client, call } = useApi()
  const names = ref<string[]>([])

  async function load() {
    try {
      const { data } = await call(client.GET('/config'), { toast: false })
      names.value = (data.global?.ip_lists ?? []).map((l) => l.name)
    } catch {
      names.value = []
    }
  }

  return { names, load }
}
