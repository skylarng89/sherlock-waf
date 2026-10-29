import { ref } from 'vue'
import { useApi } from '@/api/useApi'
import { ApiError } from '@/api/errors'
import type { Policy } from './layers'
import type { Site } from './siteDraft'

export type LoadState = 'loading' | 'ready' | 'missing' | 'error'

/**
 * Loads the site list (for the ETag and the site's index, which the server uses in
 * `/sites/<index>/...` error pointers) and the global defaults (the inherited layer).
 */
export function useSiteContext(siteId: () => string | undefined) {
  const { client, call } = useApi()
  const state = ref<LoadState>('loading')
  const sites = ref<Site[]>([])
  const site = ref<Site>()
  const index = ref(-1)
  const etag = ref<string>()
  const defaults = ref<Policy>({})
  const loadError = ref<ApiError>()

  async function load() {
    state.value = 'loading'
    loadError.value = undefined
    try {
      const [list, def] = await Promise.all([
        // A node with no configuration yet may answer 404; that is an empty site list.
        call(client.GET('/sites'), { toast: false }).catch((e: unknown) => {
          if (e instanceof ApiError && e.kind === 'not_found') {
            return { data: { items: [] as Site[] }, etag: undefined }
          }
          throw e
        }),
        call(client.GET('/defaults'), { toast: false }).catch((e: unknown) => {
          if (e instanceof ApiError && e.kind === 'not_found') return undefined
          throw e
        }),
      ])
      sites.value = list.data.items
      etag.value = list.etag
      defaults.value = def?.data ?? {}
      const id = siteId()
      index.value = id === undefined ? -1 : sites.value.findIndex((s) => s.id === id)
      site.value = index.value >= 0 ? sites.value[index.value] : undefined
      state.value = id === undefined || site.value ? 'ready' : 'missing'
    } catch (e) {
      loadError.value = e instanceof ApiError ? e : undefined
      state.value = 'error'
    }
  }

  return { state, sites, site, index, etag, defaults, loadError, load }
}
