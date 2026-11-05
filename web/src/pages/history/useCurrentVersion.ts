import { ref } from 'vue'
import { useApi } from '@/api/useApi'

/** ETag values are quoted (and possibly weak); version ids are the bare token. */
export function etagToId(etag: string | undefined): string | undefined {
  if (!etag) return undefined
  return etag.replace(/^W\//, '').replace(/^"|"$/g, '')
}

/** The head ETag of the live configuration: the rollback precondition and the "current" marker. */
export function useCurrentVersion() {
  const { client, call } = useApi()
  const etag = ref<string>()

  async function refresh(): Promise<string | undefined> {
    const res = await call(client.GET('/config'), { toast: false })
    etag.value = res.etag
    return res.etag
  }

  return { etag, refresh }
}
