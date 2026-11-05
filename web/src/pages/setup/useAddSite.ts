import { ApiError } from '@/api/errors'
import type { components } from '@/api/schema'
import { useApi } from '@/api/useApi'
import { rebaseFieldErrors } from '@/pages/sites/lib/rebase'
import type { Site } from '@/pages/sites/lib/siteDraft'

/**
 * Adds a site during setup. A fresh node has no configuration, so the very first write
 * is `PUT /config` with a complete body and no If-Match; once one exists, `POST /sites`
 * with the ETag we just read. Field errors come back rebased onto the site's own paths.
 */
export function useAddSite() {
  const { client, call, ifMatch } = useApi()

  async function addSite(site: Site): Promise<void> {
    let etag: string | undefined
    let existing: components['schemas']['Config'] | undefined
    try {
      const res = await call(client.GET('/config'), { toast: false })
      etag = res.etag
      existing = res.data
    } catch (e) {
      if (!(e instanceof ApiError && e.kind === 'not_found')) throw e
    }
    const index = existing?.sites.length ?? 0
    try {
      if (etag) {
        await call(client.POST('/sites', { params: { header: ifMatch(etag) }, body: site }), {
          toast: false,
        })
      } else {
        await call(
          client.PUT('/config', {
            // Spec gap: If-Match is declared required, but the first config has no version.
            params: { header: {} as { 'If-Match': string } },
            body: {
              schema_version: existing?.schema_version ?? 1,
              ...(existing?.global ? { global: existing.global } : {}),
              sites: [...(existing?.sites ?? []), site],
            },
          }),
          { toast: false },
        )
      }
    } catch (e) {
      throw rebaseFieldErrors(e, {
        prefixes: [`/sites/${index}`],
        lists: ['hosts', 'upstreams.targets'],
      })
    }
  }

  return { addSite }
}
