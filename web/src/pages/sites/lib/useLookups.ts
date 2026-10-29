import { ref } from 'vue'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'

type Certificate = components['schemas']['Certificate']

/** Pickers: uploaded certificates and block-page template ids ("default" always exists). */
export function useLookups() {
  const { client, call } = useApi()
  const certificates = ref<Certificate[]>([])
  const blockPages = ref<string[]>(['default'])

  async function load() {
    const [certs, pages] = await Promise.allSettled([
      call(client.GET('/certificates'), { toast: false }),
      call(client.GET('/block-pages'), { toast: false }),
    ])
    if (certs.status === 'fulfilled') certificates.value = certs.value.data.items
    if (pages.status === 'fulfilled') {
      blockPages.value = [...new Set(['default', ...pages.value.data.items.map((p) => p.id)])]
    }
  }

  return { certificates, blockPages, load }
}
