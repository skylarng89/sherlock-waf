import type { components } from '@/api/schema'
import { parseDuration } from '@/pages/login/policy'
import { clone, getAt, mergePatch, setAt, type JsonObject } from './lib/json'

type Policy = components['schemas']['Policy']

/**
 * The recommended finance settings (M11-T3). The mode is deliberately not part of it:
 * switching a site to block is a separate decision. The login endpoints are not either,
 * because only the operator knows where the login form posts.
 */
export const BASELINE: { path: string; value: unknown }[] = [
  { path: 'login_protection.enabled', value: true },
  { path: 'login_protection.thresholds.per_ip', value: 20 },
  { path: 'login_protection.thresholds.per_username', value: 5 },
  { path: 'login_protection.thresholds.per_device', value: 10 },
  { path: 'login_protection.thresholds.window', value: '10m' },
  { path: 'login_protection.action', value: 'challenge' },
  { path: 'dlp.enabled', value: true },
  { path: 'dlp.detect', value: ['pan', 'iban'] },
  { path: 'dlp.action', value: 'mask' },
  { path: 'bot.enabled', value: true },
  { path: 'bot.challenge', value: 'pow' },
]

/**
 * set: nothing there yet, will be written. unchanged: already equal. kept: the operator
 * (or the global defaults) chose something else and it stays unless they opt in to
 * replacing it. overwrite: they opted in.
 */
export type RowStatus = 'set' | 'unchanged' | 'kept' | 'overwrite'

export interface PresetRow {
  path: string
  current: unknown
  baseline: unknown
  status: RowStatus
}

export interface PresetPlan {
  rows: PresetRow[]
  /** The JSON merge patch for PATCH /sites/{site}, undefined when nothing changes. */
  patch: JsonObject | undefined
  /** The mode that applies to the site (site, then global defaults, then the built-in detect). */
  mode: string
  /** True when findings are only recorded, so the baseline will not enforce anything yet. */
  modeHint: boolean
  /** True when no login endpoint is declared at the site or in the defaults. */
  needsEndpoints: boolean
}

function same(path: string, a: unknown, b: unknown): boolean {
  if (path.endsWith('.window') && typeof a === 'string' && typeof b === 'string') {
    const x = parseDuration(a)
    return x !== undefined && x === parseDuration(b)
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    return JSON.stringify([...a].map(String).sort()) === JSON.stringify([...b].map(String).sort())
  }
  return JSON.stringify(a) === JSON.stringify(b)
}

/**
 * Works out what applying the baseline to `policy` (the site-level policy) would do.
 * `defaults` is the global policy layer: a value set there counts as the operator's
 * choice. Paths in `overwrite` replace a differing value instead of keeping it.
 */
export function planBaseline(
  policy: Policy | undefined,
  defaults: Policy | undefined,
  overwrite: ReadonlySet<string> = new Set(),
): PresetPlan {
  const site = (policy ?? {}) as JsonObject
  let after = clone(site)
  const rows: PresetRow[] = BASELINE.map(({ path, value }) => {
    const own = getAt(site, path)
    const current = own ?? getAt(defaults, path)
    let status: RowStatus
    if (current === undefined) status = 'set'
    else if (same(path, current, value)) status = 'unchanged'
    else status = overwrite.has(path) ? 'overwrite' : 'kept'
    // An inherited value that already matches needs no site-level copy.
    if (status === 'set' || status === 'overwrite') after = setAt(after, path, value)
    return { path, current, baseline: value, status }
  })
  const mode = String(site.mode ?? getAt(defaults, 'mode') ?? 'detect')
  const hasEndpoints = (p: unknown) => {
    const list = getAt(p, 'login_protection.endpoints')
    return Array.isArray(list) && list.length > 0
  }
  return {
    rows,
    patch: mergePatch({ policy: site }, { policy: after }),
    mode,
    modeHint: mode !== 'block',
    needsEndpoints: !hasEndpoints(site) && !hasEndpoints(defaults),
  }
}

/** Rows whose value differs from the baseline and can therefore be replaced on request. */
export const conflicts = (plan: PresetPlan): PresetRow[] =>
  plan.rows.filter((r) => r.status === 'kept' || r.status === 'overwrite')
