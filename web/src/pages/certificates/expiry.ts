export type ExpiryState = 'ok' | 'warning' | 'expired'

export const WARNING_DAYS = 30
const DAY_MS = 86_400_000

export interface Expiry {
  state: ExpiryState
  /** Whole days left; negative once expired. */
  days: number
}

/** `now` is injected so callers and tests never depend on the wall clock. */
export function expiryOf(notAfter: string, now: number): Expiry {
  const end = Date.parse(notAfter)
  if (Number.isNaN(end) || end <= now)
    return { state: 'expired', days: Math.floor((end - now) / DAY_MS) }
  const days = Math.floor((end - now) / DAY_MS)
  return { state: days <= WARNING_DAYS ? 'warning' : 'ok', days }
}
