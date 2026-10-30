import { useToastStore } from '@/stores/toasts'
import { client, ifMatch, unwrap, type ApiResult } from './client'
import { ApiError } from './errors'

interface RawResult<D> {
  data?: D
  error?: unknown
  response: Response
}

export interface CallOptions {
  /** Set false when the caller renders the error itself (inline banner, stale-reload prompt). */
  toast?: boolean
}

/**
 * The page-author entry point.
 *
 *   const { client, call, ifMatch } = useApi()
 *   const { data, etag } = await call(client.GET('/sites'))
 *   await call(client.PUT('/sites/{site}', { params: { path: { site }, header: ifMatch(etag) }, body }))
 *
 * `call` throws ApiError (StaleConfigError for 412). It shows a toast for errors the
 * page cannot render in a field, and stays silent for field errors (use `useFormErrors`)
 * and 401 (the session store redirects to /login).
 */
export function useApi() {
  const toasts = useToastStore()

  async function call<D>(
    request: Promise<RawResult<D>>,
    options: CallOptions = {},
  ): Promise<ApiResult<D>> {
    try {
      return await unwrap(request)
    } catch (e) {
      if (e instanceof ApiError && options.toast !== false && shouldToast(e)) toasts.error(e)
      throw e
    }
  }

  return { client, call, ifMatch }
}

function shouldToast(e: ApiError): boolean {
  if (e.kind === 'unauthenticated') return false
  if (e.kind === 'validation' && e.hasFieldErrors) return false
  return true
}
