import { isObject, type JsonObject } from '@/pages/sites/lib/json'

export const GEOIP_PROVIDERS = ['dbip-lite', 'maxmind'] as const
export const REPUTATION_LISTS = ['firehol_level1', 'spamhaus_drop'] as const
/** The MaxMind provider is accepted by the schema but not implemented in the data plane yet. */
export const MAXMIND_IMPLEMENTED = false
/** Where an operator places a GeoIP file by hand (there is no upload API yet), under the data dir. */
export const GEOIP_MANUAL_PATH = 'geoip/dbip-country-lite.csv.gz'

export interface FeedDraft {
  geoip: { provider: string; auto_update: boolean }
  reputation_lists: string[]
  crowdsec: { enabled: boolean; lapi_url: string; allow_private: boolean }
}

const str = (v: unknown, fallback: string) => (typeof v === 'string' ? v : fallback)
const bool = (v: unknown, fallback: boolean) => (typeof v === 'boolean' ? v : fallback)
const rec = (v: unknown): JsonObject => (isObject(v) ? v : {})

/** `global.feeds` is an open object in the spec; read only the keys this form owns. */
export function toDraft(feeds: Record<string, unknown> | undefined): FeedDraft {
  const geoip = rec(feeds?.geoip)
  const crowdsec = rec(feeds?.crowdsec)
  const lists = feeds?.reputation_lists
  return {
    geoip: {
      provider: str(geoip.provider, 'dbip-lite'),
      auto_update: bool(geoip.auto_update, true),
    },
    reputation_lists: Array.isArray(lists) ? lists.map(String) : [],
    crowdsec: {
      enabled: bool(crowdsec.enabled, false),
      lapi_url: str(crowdsec.lapi_url, ''),
      allow_private: bool(crowdsec.allow_private, false),
    },
  }
}

/** Writes the draft over the stored object, keeping keys this form does not know about. */
export function fromDraft(
  feeds: Record<string, unknown> | undefined,
  draft: FeedDraft,
): Record<string, unknown> {
  return {
    ...feeds,
    geoip: { ...rec(feeds?.geoip), ...draft.geoip },
    reputation_lists: [...draft.reputation_lists],
    crowdsec: { ...rec(feeds?.crowdsec), ...draft.crowdsec },
  }
}
