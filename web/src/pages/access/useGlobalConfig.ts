import { ref } from 'vue'
import { ApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import { clone } from '@/pages/sites/lib/json'

export type Config = components['schemas']['Config']
export type IpList = NonNullable<NonNullable<Config['global']>['ip_lists']>[number]

/**
 * The whole configuration document. IP lists and feeds have no endpoints of their own, so they
 * are edited by reading the document, changing `global`, and writing it back with If-Match.
 * `save` applies only the caller's change to the freshest known copy, so one section's
 * unsaved edits are never written by another section's save.
 */
export function useGlobalConfig() {
  const { client, call, ifMatch } = useApi()
  const state = ref<'loading' | 'ready' | 'error'>('loading')
  const config = ref<Config>({ schema_version: 1, sites: [] })
  const etag = ref<string>()

  async function load() {
    state.value = 'loading'
    try {
      const res = await call(client.GET('/config'), { toast: false })
      config.value = res.data
      etag.value = res.etag
      state.value = 'ready'
    } catch (e) {
      // No configuration stored yet: start from an empty document, created by the first save.
      if (e instanceof ApiError && e.kind === 'not_found') {
        config.value = { schema_version: 1, sites: [] }
        etag.value = undefined
        state.value = 'ready'
      } else {
        state.value = 'error'
      }
    }
  }

  /** Throws ApiError (412, 428, 422 ...) for the caller's write flow to route. */
  async function save(change: (draft: Config) => void): Promise<void> {
    const next = clone(config.value)
    change(next)
    const res = await call(
      client.PUT('/config', {
        params: { header: etag.value ? ifMatch(etag.value) : {} },
        body: next,
      }),
      { toast: false },
    )
    config.value = next
    etag.value = res.etag ?? etag.value
  }

  return { state, config, etag, load, save }
}

export type GlobalConfigStore = ReturnType<typeof useGlobalConfig>
